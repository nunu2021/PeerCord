package impl

import (
	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
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

func (n *node) Multicast(msg transport.Message, recipients map[string]struct{}) error {
	/*multicastMsg := types.MulticastMessage{
		Recipients: recipients,
		Msg:        &msg,
	}*/

	return n.NaiveMulticast(msg, recipients)
}
