package types

type EigenTrustRequestMessage struct {
	KStep        uint
	Source       string
	IncludeLocal bool
}

type EigenTrustResponseMessage struct {
	KStep  uint
	Source string
	Value  float64
	IsPVal bool
}
