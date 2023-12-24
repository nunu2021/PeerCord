package types

import "fmt"

// -----------------------------------------------------------------------------
// GroupCallDHIndividual

// NewEmpty implements types.Message.
func (m GroupCallDHIndividual) NewEmpty() Message {
	return &GroupCallDHIndividual{}
}

// Name implements types.Message.
func (m GroupCallDHIndividual) Name() string {
	return "GroupCallDHIndividual"
}

// String implements types.Message.
func (m GroupCallDHIndividual) String() string {
	return fmt.Sprintf("{GroupCallDHIndividual %v}", m.RemoteKey)
}

// HTML implements types.Message.
func (m GroupCallDHIndividual) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// GroupCallDHSharedSecret

// NewEmpty implements types.Message.
func (m GroupCallDHSharedSecret) NewEmpty() Message {
	return &GroupCallDHSharedSecret{}
}

// Name implements types.Message.
func (m GroupCallDHSharedSecret) Name() string {
	return "GroupCallDHSharedSecret"
}

// String implements types.Message.
func (m GroupCallDHSharedSecret) String() string {
	return fmt.Sprintf("{GroupCallDHSharedSecret %v}", m.RemoteKey)
}

// HTML implements types.Message.
func (m GroupCallDHSharedSecret) HTML() string {
	return m.String()
}
