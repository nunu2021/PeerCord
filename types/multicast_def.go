package types

import "go.dedis.ch/cs438/transport"

// JoinMulticastGroupRequestMessage is sent by a peer when it wants to join a
// multicast group. Sending this packet is used to build the spanning tree on the
// fly.
type JoinMulticastGroupRequestMessage struct {
	Source string // Peer the is multicasting
	Id     string
}

// MulticastMessage represents a message that is sent to many peers at the same time
type MulticastMessage struct {
	// Set of the addresses of the peers that should receive the message
	Recipients map[string]struct{}

	// The embedded message
	Msg *transport.Message
}
