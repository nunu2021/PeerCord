package types

import "fmt"

// -----------------------------------------------------------------------------
// PKRequestMessage

// NewEmpty implements types.Message.
func (m PKRequestMessage) NewEmpty() Message {
	return &PKRequestMessage{}
}

// Name implements types.Message.
func (m PKRequestMessage) Name() string {
	return "PKRequestMessage"
}

// String implements types.Message.
func (m PKRequestMessage) String() string {
	return fmt.Sprintf("{PKRequestMessage %v - %v - %v}", m.PeerId, m.PubId, m.PubKeyBytes)
}

// HTML implements types.Message.
func (m PKRequestMessage) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// PKResponseMessage

// NewEmpty implements types.Message.
func (m PKResponseMessage) NewEmpty() Message {
	return &PKResponseMessage{}
}

// Name implements types.Message.
func (m PKResponseMessage) Name() string {
	return "PKResponseMessage"
}

// String implements types.Message.
func (m PKResponseMessage) String() string {
	return fmt.Sprintf("{PKResponseMessage %v - %v - %v}", m.PeerId, m.PubId, m.PubKeyBytes)
}

// HTML implements types.Message.
func (m PKResponseMessage) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// DialMsg

// NewEmpty implements types.Message.
func (m DialMsg) NewEmpty() Message {
	return &DialMsg{}
}

// Name implements types.Message.
func (m DialMsg) Name() string {
	return "DialMsg"
}

// String implements types.Message.
func (m DialMsg) String() string {
	return fmt.Sprintf("{DialMsg %v - %v - %v - %v}", m.CallId, m.Caller, m.PubId, m.Members)
}

// HTML implements types.Message.
func (m DialMsg) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// DialResponseMsg

// NewEmpty implements types.Message.
func (m DialResponseMsg) NewEmpty() Message {
	return &DialResponseMsg{}
}

// Name implements types.Message.
func (m DialResponseMsg) Name() string {
	return "DialResponseMsg"
}

// String implements types.Message.
func (m DialResponseMsg) String() string {
	return fmt.Sprintf("{DialResponseMsg %v - %v - %v}", m.CallId, m.PubId, m.Accepted)
}

// HTML implements types.Message.
func (m DialResponseMsg) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// HangUpMsg

// NewEmpty implements types.Message.
func (m HangUpMsg) NewEmpty() Message {
	return &HangUpMsg{}
}

// Name implements types.Message.
func (m HangUpMsg) Name() string {
	return "HangUpMsg"
}

// String implements types.Message.
func (m HangUpMsg) String() string {
	return fmt.Sprintf("{HangUpMsg %v - %v}", m.Member, m.CallId)
}

// HTML implements types.Message.
func (m HangUpMsg) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// GroupCallVotePkt

// NewEmpty implements types.Message.
func (m GroupCallVotePkt) NewEmpty() Message {
	return &GroupCallVotePkt{}
}

// Name implements types.Message.
func (m GroupCallVotePkt) Name() string {
	return "GroupCallVotePkt"
}

// String implements types.Message.
func (m GroupCallVotePkt) String() string {
	return fmt.Sprintf("{GroupCallVotePkt %v - %v - %v -  %v - %v}", m.Voter, m.ID, m.Type, m.Decision, m.Meta)
}

// HTML implements types.Message.
func (m GroupCallVotePkt) HTML() string {
	return m.String()
}
