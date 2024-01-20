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
	return fmt.Sprintf("join multicast group %s (sender: %s) of request", msg.GroupID, msg.GroupSender)
}

// HTML implements types.Message.
func (msg JoinMulticastGroupRequestMessage) HTML() string {
	return msg.String()
}

// -----------------------------------------------------------------------------
// LeaveMulticastGroupRequestMessage

// NewEmpty implements types.Message.
func (msg LeaveMulticastGroupRequestMessage) NewEmpty() Message {
	return &LeaveMulticastGroupRequestMessage{}
}

// Name implements types.Message.
func (msg LeaveMulticastGroupRequestMessage) Name() string {
	return "leave multicast group request"
}

// String implements types.Message.
func (msg LeaveMulticastGroupRequestMessage) String() string {
	return fmt.Sprintf("leave multicast group %s request", msg.GroupID)
}

// HTML implements types.Message.
func (msg LeaveMulticastGroupRequestMessage) HTML() string {
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
	return "multicast message"
}

// HTML implements types.Message.
func (msg MulticastMessage) HTML() string {
	return msg.String()
}

// -----------------------------------------------------------------------------
// MulticastGroupExistence

// NewEmpty implements types.Message.
func (msg MulticastGroupExistence) NewEmpty() Message {
	return &MulticastGroupExistence{}
}

// Name implements types.Message.
func (msg MulticastGroupExistence) Name() string {
	return "multicast group existence message"
}

// String implements types.Message.
func (msg MulticastGroupExistence) String() string {
	return "multicast group existence message " + msg.GroupID + " " + msg.GroupSender
}

// HTML implements types.Message.
func (msg MulticastGroupExistence) HTML() string {
	return msg.String()
}
