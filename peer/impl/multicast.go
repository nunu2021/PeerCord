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
	sender   string
	forwards map[string]struct{}
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
		sender:   n.GetAddress(),
		forwards: make(map[string]struct{}),
	}
	return id
}

// DeleteMulticastGroup deletes an existing multicast group. It sends a messages
// to all the peers of the group to inform them of the deletion.
func (n *node) DeleteMulticastGroup(id string) error {
	_, ok := n.multicast.groups[id]
	if !ok {
		return UnknownMulticastGroupError(id)
	}

	return nil
}

// JoinMulticastGroup allows a peer to be added to the multicast group with the
// given id and created by the given peer. It sends a packet containing the
// request to join the group. It blocks until the request is accepted, retrying
// if needed.
func (n *node) JoinMulticastGroup(peer string, id string) error {
	// Send the request
	req := types.JoinMulticastGroupRequestMessage{
		ID: id,
	}

	err := n.marshalAndUnicast(peer, req)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't unicast join multicast group request")
		return err
	}

	// TODO wait until an ack is received, retry if needed

	return nil
}

// LeaveMulticastGroup allows a peer to leave the multicast group with the
// given id and created by the given peer. It sends a packet containing the
// request to leave the group.
func (n *node) LeaveMulticastGroup(peer string, id string) error {
	// Send the request
	req := types.LeaveMulticastGroupRequestMessage{
		ID: id,
	}

	err := n.marshalAndUnicast(peer, req)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't unicast leave multicast group request")
		return err
	}

	// TODO wait for an ACK?

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

	for dest := range group.forwards {
		err := n.marshalAndUnicast(dest, multicastMsg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't unicast message for multicast")
			return err
		}
	}

	return nil
}
