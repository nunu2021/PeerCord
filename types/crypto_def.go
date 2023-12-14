package types

import "crypto/ecdh"

type GroupCallDHUpward struct {
	Curve              ecdh.Curve
	PreviousKeys       []ecdh.PublicKey
	RemainingReceivers []string
}

type GroupCallDHDownward struct {
	Curve        ecdh.Curve
	PreviousKeys []ecdh.PublicKey
}
