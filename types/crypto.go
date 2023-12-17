package types

import "fmt"

// -----------------------------------------------------------------------------
// GroupCallDHUpward

// NewEmpty implements types.Message.
func (m GroupCallDHUpward) NewEmpty() Message {
	return &GroupCallDHUpward{}
}

// Name implements types.Message.
func (m GroupCallDHUpward) Name() string {
	return "GroupCallDHUpward"
}

// String implements types.Message.
func (m GroupCallDHUpward) String() string {
	return fmt.Sprintf("{GroupCallDHUpward %v - %v}", m.PreviousKeys, m.RemainingReceivers)
}

// HTML implements types.Message.
func (m GroupCallDHUpward) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// PaxosPrepareMessage

// NewEmpty implements types.Message.
func (m GroupCallDHDownward) NewEmpty() Message {
	return &GroupCallDHDownward{}
}

// Name implements types.Message.
func (m GroupCallDHDownward) Name() string {
	return "GroupCallDHDownward"
}

// String implements types.Message.
func (m GroupCallDHDownward) String() string {
	return fmt.Sprintf("{GroupCallDHDownward %v}", m.PreviousKeys)
}

// HTML implements types.Message.
func (m GroupCallDHDownward) HTML() string {
	return m.String()
}
