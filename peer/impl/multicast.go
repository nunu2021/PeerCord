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

type Multicast struct {
	// Contains the IDs of the multicast groups
	groups map[string]struct{}
}

func NewMulticast() Multicast {
	return Multicast{
		groups: make(map[string]struct{}),
	}
}

// NewMulticastGroup creates a new multicast group and returns its ID. The other
// peers need this ID to join the group
func (n *node) NewMulticastGroup() string {
	id := xid.New().String()
	n.multicast.groups[id] = struct{}{}
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
		Source: peer,
		Id:     id,
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
		Source: peer,
		Id:     id,
	}

	err := n.marshalAndUnicast(peer, req)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't unicast leave multicast group request")
		return err
	}

	// TODO wait for an ACK?

	return nil
}

func (n *node) Multicast(msg transport.Message, recipients map[string]struct{}) error {
	/*multicastMsg := types.MulticastMessage{
		Recipients: recipients,
		Msg:        &msg,
	}*/

	return n.NaiveMulticast(msg, recipients)
}
