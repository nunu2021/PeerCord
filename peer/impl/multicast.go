package impl

import (
	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"sync"
	"time"
)

func (n *node) NaiveMulticast(msg transport.Message, recipients map[string]struct{}) error {
	for dest := range recipients {
		err := n.Unicast(dest, msg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't unicast message")
			return err
		}
	}

	return nil
}

// MulticastGroup contains information about a multicast group:
// - the sender
// - the neighbors to forward
type MulticastGroup struct {
	// Peer that is sending messages to the multicast group. It is the root of
	// the tree.
	sender string

	// Address of the father of the peer in the tree.  This information is
	// stored because the routing table may change.
	// If the peer is the sender of the group, it is an empty string
	nextHopToSender string

	// Set of the neighbors that the peer should forward the messages to.
	forwards map[string]ForwardsInfo

	// Indicates if the peer belongs to the multicast group and should
	// process the messages.
	isInGroup bool

	// Must be locked when using the multicast group
	mtx sync.Mutex
}

// ForwardsInfo contains information used to communicate with the goroutine
// monitoring the neighbor.
type ForwardsInfo struct {
	// A message is sent to the channel when the neighbor sends a request to
	// join the multicast group (in order to stay in the group).
	joinEvents chan struct{}

	// A message is sent to the channel when the neighbor sends a request to
	// leave the multicast group.
	leaveEvents chan struct{}
}

type Multicast struct {
	// Information about each multicast group.
	// The sender may be the node itself.
	groups safeMap[string, *MulticastGroup]
}

func NewMulticast() Multicast {
	return Multicast{
		groups: newSafeMap[string, *MulticastGroup](),
	}
}

// Goroutine in charge of monitoring a neighbor that we are forwarding messages
// to. It manages the timers, processes the join / leave requests and remove the
// neighbor from the forwarding table when it is no longer needed
func (n *node) watchNeighbor(group *MulticastGroup, neighbor string) {
	group.mtx.Lock()
	info, ok := group.forwards[neighbor]
	if !ok {
		n.logger.Warn().Msg("can't find neighbor in forwarding table: already deleted?")
		return
	}
	leaveEvents, joinEvents := info.leaveEvents, info.joinEvents
	group.mtx.Unlock()

	// Date at which the last event (join or leave) was received.
	lastEvent := time.Now()

	// If the neighbor has sent a request to leave the group, becomes true
	// until the group is actually deleted
	toBeDeleted := false

	isDeleted := false

	for !isDeleted {
		if toBeDeleted {
			select {
			case <-leaveEvents:
				// Here, we ignore leave events

			case <-joinEvents:
				toBeDeleted = false
				lastEvent = time.Now()

			case <-time.After(time.Until(lastEvent.Add(n.conf.MulticastLeaveTimeout))):
				// Anything new since the leave event, we stop forwarding
				isDeleted = true
			}
		} else { // Active state
			select {
			case <-leaveEvents:
				toBeDeleted = true
				lastEvent = time.Now()

			case <-joinEvents:
				lastEvent = time.Now()

			case <-time.After(time.Until(lastEvent.Add(n.conf.MulticastJoinTimeout))):
				// No join event received for a long time, we stop forwarding
				isDeleted = true
			}
		}
	}

	// The neighbor must be removed from the forwarding table
	group.mtx.Lock()
	delete(group.forwards, neighbor)
	group.mtx.Unlock()
}

// Goroutine in charge of monitoring a multicast group. It resends periodically
// join messages so that the peer stays in the group. If the group is not needed
// anymore (the forwarding table is empty and the peer doesn't process the
// messages), it leaves the group's tree.
func (n *node) watchMulticastGroup(groupID string) {
	group, ok := n.multicast.groups.get(groupID)
	if !ok {
		n.logger.Error().Msg("group does not exist")
		return
	}

	for {
		group.mtx.Lock()

		// Delete the group if it is no longer needed
		if group.sender != n.GetAddress() && len(group.forwards) == 0 && !group.isInGroup {
			n.multicast.groups.delete(groupID)

			req := types.LeaveMulticastGroupRequestMessage{
				GroupID: groupID,
			}

			err := n.marshalAndUnicast(group.nextHopToSender, req)
			if err != nil {
				n.logger.Error().Err(err).Msg("can't unicast leave multicast group request")
			}

			return
		}

		group.mtx.Unlock()

		// Send a join message
		if group.sender != n.GetAddress() {
			req := types.JoinMulticastGroupRequestMessage{
				GroupSender: group.sender,
				GroupID:     groupID,
			}

			err := n.marshalAndUnicast(group.nextHopToSender, req)
			if err != nil {
				n.logger.Error().Err(err).Msg("can't unicast join multicast group request")
				return
			}
		}

		// Wait until the next join message
		time.Sleep(n.conf.MulticastResendJoinInterval)
	}
}

// NewMulticastGroup creates a new multicast group and returns its ID. The other
// peers need this ID to join the group
func (n *node) NewMulticastGroup() string {
	id := xid.New().String()
	n.multicast.groups.set(id, &MulticastGroup{
		sender:          n.GetAddress(),
		nextHopToSender: "",
		forwards:        make(map[string]ForwardsInfo),
		isInGroup:       false,
	})
	go n.watchMulticastGroup(id)
	return id
}

// DeleteMulticastGroup deletes an existing multicast group. It sends a message
// to all the peers of the group to inform them of the deletion.
func (n *node) DeleteMulticastGroup(id string) error {
	_, ok := n.multicast.groups.get(id)
	if !ok {
		return UnknownMulticastGroupError(id)
	}

	// TODO

	return nil
}

// Internal function allowing a peer to request receiving the messages of a
// multicast group without actually joining the group: it will not process the
// messages.  The function sends a packet containing the request to join the
// group. It blocks until the request is accepted, retrying if needed.
func (n *node) joinMulticastTree(groupSender string, groupID string) error {
	n.multicast.groups.lock()
	defer n.multicast.groups.unlock()

	// Nothing to do
	_, exists := n.multicast.groups.unsafeGet(groupID)
	if exists {
		return nil
	}

	// The group does not exist
	if groupSender == n.GetAddress() {
		return UnknownMulticastGroupError(groupID)
	}

	// Find the next hop
	next, exists := n.routingTable.get(groupSender)
	if !exists {
		err := RoutingError{SourceAddr: n.GetAddress(), DestAddr: groupSender}
		n.logger.Warn().Err(err).Msg("can't send packet: unknown route")
		return err
	}

	// Create the group
	n.multicast.groups.unsafeSet(groupID, &MulticastGroup{
		sender:          groupSender,
		nextHopToSender: next,
		forwards:        make(map[string]ForwardsInfo),
		isInGroup:       false,
	})
	go n.watchMulticastGroup(groupID)

	return nil
}

// JoinMulticastGroup allows a peer to be added to the multicast group with the
// given id and created by the given peer.
func (n *node) JoinMulticastGroup(groupSender string, groupID string) error {
	err := n.joinMulticastTree(groupSender, groupID)
	if err != nil {
		return err
	}

	group, ok := n.multicast.groups.get(groupID)
	if !ok {
		err := UnknownMulticastGroupError(groupID)
		n.logger.Error().Err(err).Msg("can't find new group: was it already deleted?")
		return err
	}

	group.mtx.Lock()
	group.isInGroup = true
	group.mtx.Unlock()

	return nil
}

// LeaveMulticastGroup allows a peer to leave the multicast group with the
// given id and created by the given peer. It sends a packet containing the
// request to leave the group.
func (n *node) LeaveMulticastGroup(groupSender string, groupID string) error {
	group, ok := n.multicast.groups.get(groupID)
	if !ok {
		n.logger.Info().Str("groupID", groupID).Msg("can't leave unknown group")
		return nil
	}
	group.mtx.Lock()
	defer group.mtx.Unlock()

	if !group.isInGroup {
		n.logger.Info().Str("groupID", groupID).Msg("can't leave unjoined group")
		return nil
	}

	group.isInGroup = false

	return nil
}

func (n *node) receiveJoinMulticastGroupMessage(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.JoinMulticastGroupRequestMessage)
	if !ok {
		panic("not a join multicast group request message")
	}

	group, ok := n.multicast.groups.get(msg.GroupID)

	// TODO do this in another goroutine to avoid blocking the reception of messages

	// If the peer is not already in the tree
	if !ok {
		err := n.joinMulticastTree(msg.GroupSender, msg.GroupID)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't join multicast group")
			return err
		}

		group, ok = n.multicast.groups.get(msg.GroupID)
		if !ok {
			err := UnknownMulticastGroupError(msg.GroupID)
			n.logger.Error().Err(err).Msg("can't find new group: was it already deleted?")
			return err
		}
	}

	group.mtx.Lock()
	defer group.mtx.Unlock()

	info, ok := group.forwards[pkt.Header.Source]
	if ok {
		// Notify the goroutine that a join message has been received
		info.joinEvents <- struct{}{}
	} else {
		// Create a new entry in the forwarding table
		group.forwards[pkt.Header.Source] = ForwardsInfo{
			joinEvents:  make(chan struct{}),
			leaveEvents: make(chan struct{}),
		}

		// Start the goroutine monitoring the neighbor
		go n.watchNeighbor(group, pkt.Header.Source)
	}

	return nil
}

func (n *node) receiveLeaveMulticastGroupMessage(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.LeaveMulticastGroupRequestMessage)
	if !ok {
		panic("not a leave multicast group request message")
	}

	group, ok := n.multicast.groups.get(msg.GroupID)
	if !ok {
		n.logger.Warn().Str("groupID", msg.GroupID).Msg("can't leave unknown group")
		return nil
	}

	group.mtx.Lock()
	defer group.mtx.Unlock()

	info, ok := group.forwards[pkt.Header.Source]
	if !ok {
		n.logger.Warn().Msg("peer does not belong to the group")
		return nil
	}

	info.leaveEvents <- struct{}{}

	return nil
}

// Given a multicast message, performs a step of the multicast algorithm:
// - transmit the messages to the children in the tree
// - process the message locally
// If isNewMessage is true, raises an error if the peer is not the sender of the
// multicast group
func (n *node) multicastStep(msg transport.Message, groupID string, isNewMessage bool) error {
	group, ok := n.multicast.groups.get(groupID)
	if !ok {
		if isNewMessage {
			n.logger.Error().Msg("can't send message to unknown multicast group")
			return UnknownMulticastGroupError(groupID)
		}
		return nil
	}

	group.mtx.Lock()

	if isNewMessage && group.sender != n.GetAddress() {
		n.logger.Error().Msg("can't send message to a multicast group of another peer")
		group.mtx.Unlock()
		return UnknownMulticastGroupError(groupID)
	}

	multicastMsg := types.MulticastMessage{
		GroupID: groupID,
		Msg:     &msg,
	}

	for dest := range group.forwards {
		err := n.marshalAndUnicast(dest, multicastMsg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't unicast message for multicast")
			group.mtx.Unlock()
			return err
		}
	}

	if group.isInGroup {
		group.mtx.Unlock()
		n.processMessage(msg)
	} else {
		group.mtx.Unlock()
	}

	return nil
}

func (n *node) Multicast(msg transport.Message, groupID string) error {
	return n.multicastStep(msg, groupID, true)
}

func (n *node) receiveMulticastMessage(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.MulticastMessage)
	if !ok {
		panic("not a multicast message")
	}

	return n.multicastStep(*msg.Msg, msg.GroupID, false)
}
