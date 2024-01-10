package types

// --------------------------

func (c CallDataMessage) NewEmpty() Message {
	return &CallDataMessage{}
}

func (c CallDataMessage) Name() string {
	return "calldata"
}

func (c CallDataMessage) String() string {
	return "calldata{}"
}

func (c CallDataMessage) HTML() string {
	return c.String()
}
