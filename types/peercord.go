package types

import "fmt"

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
	return fmt.Sprintf("{DialMsg %v - %v - %v - %v}", m.CallId, m.Caller, m.PubId, string(m.PublicKeyBytes))
}

// HTML implements types.Message.
func (m DialMsg) HTML() string {
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
