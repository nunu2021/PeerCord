package types

import "fmt"

// -----------------------------------------------------------------------------
// JoinMulticastGroupRequestMessage

// NewEmpty implements types.Message.
func (msg JoinMulticastGroupRequestMessage) NewEmpty() Message {
	return &JoinMulticastGroupRequestMessage{}
}

// Name implements types.Message.
func (msg JoinMulticastGroupRequestMessage) Name() string {
	return "join multicast group request"
}

// String implements types.Message.
func (msg JoinMulticastGroupRequestMessage) String() string {
	return fmt.Sprintf("join multicast group %s of %s request", msg.Id, msg.Source)
}

// HTML implements types.Message.
func (msg JoinMulticastGroupRequestMessage) HTML() string {
	return msg.String()
}

// -----------------------------------------------------------------------------
// MulticastMessage

// NewEmpty implements types.Message.
func (msg MulticastMessage) NewEmpty() Message {
	return &MulticastMessage{}
}

// Name implements types.Message.
func (msg MulticastMessage) Name() string {
	return "multicast message"
}

// String implements types.Message.
func (msg MulticastMessage) String() string {
	return fmt.Sprintf("multicast message")
}

// HTML implements types.Message.
func (msg MulticastMessage) HTML() string {
	return msg.String()
}
