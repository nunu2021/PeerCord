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
