package types

type GroupCallDHIndividual struct {
	RemoteKey []byte
}

type GroupCallDHSharedSecret struct {
	RemoteKey   []byte
	MembersList map[string]struct{}
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

// TODO: Does this work?
var EncryptedMsgTypes = map[string]struct{}{
	"GroupCallVotePkt": {},
	"DialMsg":          {},
}
