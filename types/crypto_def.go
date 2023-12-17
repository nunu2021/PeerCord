package types

type GroupCallDHUpward struct {
	PreviousKeys       []([]byte)
	RemainingReceivers []string
}

type GroupCallDHDownward struct {
	PreviousKeys []([]byte)
}
