package types

import "fmt"

// -----------------------------------------------------------------------------
// EigenTrustRequestMessage

// NewEmpty implements types.Message.
func (p EigenTrustRequestMessage) NewEmpty() Message {
	return &EigenTrustRequestMessage{}
}

// Name implements types.Message.
func (p EigenTrustRequestMessage) Name() string {
	return "EigenRequest"
}

// String implements types.Message.
func (p EigenTrustRequestMessage) String() string {
	return fmt.Sprintf("eigentrust request message from %s", p.Source)
}

// HTML implements types.Message.
func (p EigenTrustRequestMessage) HTML() string {
	return fmt.Sprintf("eigentrust request message from %s", p.Source)
}

// -----------------------------------------------------------------------------
// EigenTrustResponseMessage

// NewEmpty implements types.Message.
func (p EigenTrustResponseMessage) NewEmpty() Message {
	return &EigenTrustResponseMessage{}
}

// Name implements types.Message.
func (p EigenTrustResponseMessage) Name() string {
	return "EigenResponse"
}

// String implements types.Message.
func (p EigenTrustResponseMessage) String() string {
	return fmt.Sprintf("eigentrust reponse message from %s", p.Source)
}

// HTML implements types.Message.
func (p EigenTrustResponseMessage) HTML() string {
	return fmt.Sprintf("eigentrust reponse message from %s", p.Source)
}
