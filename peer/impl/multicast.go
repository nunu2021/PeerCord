package impl

import (
	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
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
	forwards map[string]struct{}

	// Indicates if the peer belongs to the multicast group and should
	// process the messages.
	isInGroup bool
}

type Multicast struct {
	// Information about each multicast group.
	// The sender may be the node itself.
	groups map[string]MulticastGroup
}

func NewMulticast() Multicast {
	return Multicast{
		groups: make(map[string]MulticastGroup),
	}
}

// NewMulticastGroup creates a new multicast group and returns its ID. The other
// peers need this ID to join the group
func (n *node) NewMulticastGroup() string {
	id := xid.New().String()
	n.multicast.groups[id] = MulticastGroup{
		sender:          n.GetAddress(),
		nextHopToSender: "",
		forwards:        make(map[string]struct{}),
		isInGroup:       false,
	}
	return id
}

// DeleteMulticastGroup deletes an existing multicast group. It sends a message
// to all the peers of the group to inform them of the deletion.
func (n *node) DeleteMulticastGroup(id string) error {
	_, ok := n.multicast.groups[id]
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
	// Nothing to do
	_, exists := n.multicast.groups[groupID]
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

	// Send the request
	req := types.JoinMulticastGroupRequestMessage{
		GroupSender: groupSender,
		GroupID:     groupID,
	}

	err := n.marshalAndUnicast(next, req)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't unicast join multicast group request")
		return err
	}

	// TODO wait until an ack is received, retry if needed

	// Create the group
	n.multicast.groups[groupID] = MulticastGroup{
		sender:          groupSender,
		nextHopToSender: next,
		forwards:        make(map[string]struct{}),
		isInGroup:       false,
	}

	return nil
}

// JoinMulticastGroup allows a peer to be added to the multicast group with the
// given id and created by the given peer.
func (n *node) JoinMulticastGroup(groupSender string, groupID string) error {
	err := n.joinMulticastTree(groupSender, groupID)
	if err != nil {
		return err
	}

	group, ok := n.multicast.groups[groupID]
	if !ok {
		err := UnknownMulticastGroupError(groupID)
		n.logger.Error().Err(err).Msg("can't find new group: was it already deleted?")
		return err
	}

	group.isInGroup = true

	return nil
}

// LeaveMulticastGroup allows a peer to leave the multicast group with the
// given id and created by the given peer. It sends a packet containing the
// request to leave the group.
func (n *node) LeaveMulticastGroup(groupSender string, id string) error {
	// TODO

	// TODO wait for an ACK?

	return nil
}

func (n *node) receiveJoinMulticastGroupMessage(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.JoinMulticastGroupRequestMessage)
	if !ok {
		panic("not a join multicast group request message")
	}

	group, ok := n.multicast.groups[msg.GroupID]

	// TODO do this in another goroutine to avoid blocking the reception of messages

	// If the peer is not already in the tree
	if !ok {
		err := n.joinMulticastTree(msg.GroupSender, msg.GroupID)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't join multicast group")
			return err
		}

		group, ok = n.multicast.groups[msg.GroupID]
		if !ok {
			err := UnknownMulticastGroupError(msg.GroupID)
			n.logger.Error().Err(err).Msg("can't find new group: was it already deleted?")
			return err
		}
	}

	// Update the forwarding table
	group.forwards[pkt.Header.Source] = struct{}{}

	return nil
}

func (n *node) receiveLeaveMulticastGroupMessage(originalMsg types.Message, pkt transport.Packet) error {
	/*msg, ok := originalMsg.(*types.LeaveMulticastGroupRequestMessage)
	if !ok {
		panic("not a leave multicast group request message")
	}*/

	return nil
}

func (n *node) Multicast(msg transport.Message, groupID string) error {
	group, ok := n.multicast.groups[groupID]
	if !ok {
		return UnknownMulticastGroupError(groupID)
	}

	multicastMsg := types.MulticastMessage{
		GroupID: groupID,
		Msg:     &msg,
	}

	if group.isInGroup {
		n.processMessage(msg)
	}

	for dest := range group.forwards {
		err := n.marshalAndUnicast(dest, multicastMsg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't unicast message for multicast")
			return err
		}
	}

	return nil
}
