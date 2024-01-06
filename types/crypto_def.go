package types

type GroupCallDHIndividual struct {
	RemoteKey []byte
}

type GroupCallDHSharedSecret struct {
	RemoteKey []byte
}

type DHEncryptedPkt struct {
	Type      string
	Payload   []byte
	RemoteKey []byte
	Signature []byte
}

type O2OEncryptedPkt struct {
	Key       []byte
	Type      string
	Payload   []byte
	RemoteID  string
	RemoteKey []byte
	Signature []byte
}
