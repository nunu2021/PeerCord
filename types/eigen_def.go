package types

type EigenTrustRequestMessage struct {
	kStep        uint
	Source       string
	IncludeLocal bool
}

type EigenTrustResponseMessage struct {
	kStep  uint
	Source string
	Value  float32
}
