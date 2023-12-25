package types

import "go.dedis.ch/cs438/transport"

// JoinMulticastGroupRequestMessage is sent by a peer when it wants to join a
// multicast group. Sending this packet is used to build the spanning tree on the
// fly.
type JoinMulticastGroupRequestMessage struct {
	ID string
}

// LeaveMulticastGroupRequestMessage is sent by a peer when it wants to leave a
// multicast group. Sending this packet updates the spanning tree
type LeaveMulticastGroupRequestMessage struct {
	ID string
}

// MulticastMessage represents a message that is sent to many peers at the same time
type MulticastMessage struct {
	// ID of the multicast group
	GroupID string

	// The embedded message
	Msg *transport.Message
}
