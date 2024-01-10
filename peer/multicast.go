package peer

import "go.dedis.ch/cs438/transport"

// Multicast defines the functions used by the peers to multicast messages
// across the network
type Multicast interface {
	// NewMulticastGroup creates a new multicast group and returns its ID. The other
	// peers need this ID to join the group
	NewMulticastGroup() string

	// DeleteMulticastGroup deletes an existing multicast group. It sends a messages
	// to all the peers of the group to inform them of the deletion.
	DeleteMulticastGroup(id string) error

	// JoinMulticastGroup allows a peer to be added to the multicast group with the
	// given id and created by the given peer. It sends a packet containing the
	// request to join the group. It blocks until the request is accepted, retrying
	// if needed.
	JoinMulticastGroup(peer string, id string) error

	// LeaveMulticastGroup allows a peer to leave the multicast group with the
	// given id and created by the given peer. It sends a packet containing the
	// request to leave the group.
	LeaveMulticastGroup(peer string, id string) error

	// Multicast sends a message to a multicast group. The peer must be the root
	// of the tree
	Multicast(msg transport.Message, groupID string) error
}
