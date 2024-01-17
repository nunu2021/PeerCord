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
	return fmt.Sprintf("{GroupCallDHSharedSecret %v - %v}", m.RemoteKey, m.MembersList)
}

// HTML implements types.Message.
func (m GroupCallDHSharedSecret) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// DHEncryptedPkt

// NewEmpty implements types.Message.
func (m DHEncryptedPkt) NewEmpty() Message {
	return &DHEncryptedPkt{}
}

// Name implements types.Message.
func (m DHEncryptedPkt) Name() string {
	return "DHEncryptedPkt"
}

// String implements types.Message.
func (m DHEncryptedPkt) String() string {
	return fmt.Sprintf("{DHEncryptedPkt %v - %v - %v - %v}", m.Type, m.Payload, m.RemoteKey, m.Signature)
}

// HTML implements types.Message.
func (m DHEncryptedPkt) HTML() string {
	return m.String()
}

// -----------------------------------------------------------------------------
// O2OEncryptedPkt

// NewEmpty implements types.Message.
func (m O2OEncryptedPkt) NewEmpty() Message {
	return &O2OEncryptedPkt{}
}

// Name implements types.Message.
func (m O2OEncryptedPkt) Name() string {
	return "O2OEncryptedPkt"
}

// String implements types.Message.
func (m O2OEncryptedPkt) String() string {
	return fmt.Sprintf("{O2OEncryptedPkt %v - %v - %v - %v - %v}", m.Key, m.Type, m.Payload, m.RemoteKey, m.Signature)
}

// HTML implements types.Message.
func (m O2OEncryptedPkt) HTML() string {
	return m.String()
}
