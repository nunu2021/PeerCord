package peer

import (
	"crypto/ecdh"
	"crypto/rsa"

	"go.dedis.ch/cs438/transport"
)

type Crypto interface {
	// Generate the Public ID
	GenerateKeyPair() error

	// Set the public ID with an external assumed hard to forge and verified id
	SetPublicID(id string)

	// Get the Public ID key
	GetPK() rsa.PublicKey

	// Get the unique id of the node
	GetPubId() string

	// Add a public ID to the known ones
	AddPublicKey(peer, pubID string, key []byte)

	// Forget about a known public ID
	RemovePublicKey(peer string)

	// Verify the public ID
	VerifyPID(peer, pubID string, key []byte) (bool, bool)

	// Sign a message with the given key
	Sign(key, msgType, packet []byte) ([]byte, error)

	// Encrypt msg for peer with its Public Key
	EncryptOneToOne(msg []byte, peer string) ([]byte, error)

	// Decrypt msg with local Secret Key
	DecryptOneToOne(msg []byte) ([]byte, error)

	// Encrypt a packet to be sent to peer with its Public Key
	EncryptOneToOneMsg(msg *transport.Message, peer string) (*transport.Message, error)

	// Generate a DH curve
	GenerateDHCurve()

	// Get the local DH curve
	GetDHCurve() ecdh.Curve

	// Generate a DH key
	GenerateDHKey() (*ecdh.PrivateKey, error)

	// Get the DH local Public Key
	GetDHPK() *ecdh.PublicKey

	// Perform an ECDH key exchange exponentiation
	ECDH(remotePK *ecdh.PublicKey) ([]byte, error)

	// Get the local DH shared secret
	GetDHSharedSecret() *ecdh.PublicKey

	// Generate a DH key
	SetDHSharedSecret(secret *ecdh.PublicKey)

	// Computes whether key and the local shared secret are equal
	DHSharedSecretEqual(key *ecdh.PublicKey) bool

	// Encrypt msg with DH shared secret
	EncryptDH(msg []byte) ([]byte, error)

	// Decrypt msg with DH shared secret
	DecryptDH(msg []byte) ([]byte, error)

	// Encrypt pkt with DH shared secret
	EncryptDHMsg(msg *transport.Message) (*transport.Message, error)

	// Start a DH Key Exchange with receivers
	StartDHKeyExchange(receivers map[string]struct{}) error

	// Remove member from the currently running group call
	GroupCallRemove(member string) error

	// Add member to the currently running group call
	GroupCallAdd(member string) error

	// End the group call
	GroupCallEnd()
}
