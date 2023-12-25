package types

type GroupCallDHIndividual struct {
	RemoteKey []byte
}

type GroupCallDHSharedSecret struct {
	RemoteKey []byte
}

type DHEncryptedPkt struct {
	Packet []byte
}

type O2OEncryptedPkt struct {
	Packet []byte
}
