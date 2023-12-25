package types

type GroupCallDHIndividual struct {
	RemoteKey []byte
}

type GroupCallDHSharedSecret struct {
	RemoteKey []byte
}

type DHEncryptedPkt struct {
	Packet    []byte
	RemoteKey []byte
	Signature []byte
}

type O2OEncryptedPkt struct {
	Key       []byte
	Packet    []byte
	RemoteKey []byte
	Signature []byte
}
