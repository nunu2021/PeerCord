package impl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"sync"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

type StrStrMap struct {
	Mutex sync.Mutex
	Map   map[string]string
}

type Crypto struct {
	KeyPair         *rsa.PrivateKey
	KnownPKs        StrStrMap
	DHCurve         ecdh.Curve
	DHPrivateKey    *ecdh.PrivateKey
	DHPublicKey     *ecdh.PublicKey
	DHSharedSecret  *ecdh.PublicKey
	RingPredecessor string
}

func (c *Crypto) GenerateKeyPair() error {
	keyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return xerrors.Errorf("error when generating keypair: %v", err)
	}
	c.KeyPair = keyPair
	return nil
}

func (c *Crypto) AddPublicKey(peer, key string) {
	c.KnownPKs.Mutex.Lock()
	c.KnownPKs.Map[peer] = key
	c.KnownPKs.Mutex.Unlock()
}

func (c *Crypto) RemovePublicKey(peer string) {
	c.KnownPKs.Mutex.Lock()
	delete(c.KnownPKs.Map, peer)
	c.KnownPKs.Mutex.Unlock()
}

func (c *Crypto) VerifyPK(peer, key string) bool {
	c.KnownPKs.Mutex.Lock()
	defer c.KnownPKs.Mutex.Unlock()
	knownKey, ok := c.KnownPKs.Map[peer]
	return ok && knownKey == key
}

func (c *Crypto) EncryptOneToOne(msg []byte, key *rsa.PublicKey) ([]byte, error) {
	encryptedMsg, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("error when encrypting a 1to1 message: %v", err)
	}
	return encryptedMsg, nil
}

func (c *Crypto) DecryptOneToOne(msg []byte) ([]byte, error) {
	decryptedMsg, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.KeyPair, msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("error when decrypting a 1to1 message: %v", err)
	}
	return decryptedMsg, nil
}

func (c *Crypto) GenerateDHCurve() {
	c.DHCurve = ecdh.X25519()
}

func (c *Crypto) EncryptDH(msg []byte) ([]byte, error) {
	key := c.DHSharedSecret.Bytes()

	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, xerrors.Errorf("error encrypting message for group call: %v", err)
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, xerrors.Errorf("error encrypting message for group call: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, xerrors.Errorf("error encrypting message for group call: %v", err)
	}

	return gcm.Seal(nonce, nonce, msg, nil), nil
}

func (c *Crypto) DecryptDH(msg []byte) ([]byte, error) {

	ciph, err := aes.NewCipher(c.DHSharedSecret.Bytes())
	if err != nil {
		return nil, xerrors.Errorf("error decrypting message for group call: %v", err)
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, xerrors.Errorf("error decrypting message for group call: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(msg) < nonceSize {
		return nil, xerrors.Errorf("error decrypting message for group call: msg size is smaller than nonce")
	}

	nonce, ciphertext := msg[:nonceSize], msg[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, xerrors.Errorf("error decrypting message for group call: %v", err)
	}
	return plaintext, nil
}

func (c *Crypto) DHUpwardStepNewValue(
	curve ecdh.Curve,
	remoteKey *ecdh.PublicKey,
) (*ecdh.PublicKey, error) {

	DHPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("error when generating DH private key: %v", err)
	}
	c.DHPrivateKey = DHPrivateKey
	c.DHPublicKey = DHPrivateKey.PublicKey()
	if remoteKey != nil {
		DHProductKey, err := c.DHPrivateKey.ECDH(remoteKey)
		if err != nil {
			return nil, xerrors.Errorf("error when generating the product of the DH keys: %v", err)
		}
		DHProductPublicKey, err := curve.NewPublicKey(DHProductKey)
		if err != nil {
			return nil, xerrors.Errorf("error when casting DH key bytes to PrivateKey: %v", err)
		}
		return DHProductPublicKey, nil
	}
	return c.DHPublicKey, nil
}

func (c *Crypto) DHDownwardStepGetSecret(
	curve ecdh.Curve,
	upstreamValues *[]([]byte),
) ([]([]byte), error) {

	downstreamValues := make([]([]byte), 0)
	upstreamLen := len(*upstreamValues)
	for i := range *upstreamValues {
		upVal := (*upstreamValues)[i]
		PK, err := x509.ParsePKIXPublicKey(upVal)
		if err != nil {
			return nil, xerrors.Errorf("error when parsing remote DH PK: %v", err)
		}
		pubKey, ok := PK.(*ecdh.PublicKey)
		if !ok {
			return nil, xerrors.Errorf("error when casting remote DH PK: type %T", PK)
		}
		downVal, err := c.DHPrivateKey.ECDH(pubKey)
		if err != nil {
			return nil, xerrors.Errorf("error in downward step when generating the product of keys: %v", err)
		}
		downValKey, err := curve.NewPublicKey(downVal)
		if err != nil {
			return nil, xerrors.Errorf("error in downward step when generating the public down value: %v", err)
		}
		if i+1 == upstreamLen {
			c.DHSharedSecret = downValKey
		} else {
			PK, err := x509.MarshalPKIXPublicKey(downValKey)
			if err != nil {
				return nil, xerrors.Errorf("error when parsing remote DH PK: %v", err)
			}
			downstreamValues = append(downstreamValues, PK)
		}
	}
	return downstreamValues, nil
}

func (n *node) StartDHKeyExchange(receivers []string) error {
	n.crypto.RingPredecessor = ""
	n.crypto.DHSharedSecret = nil
	n.crypto.DHPrivateKey = nil
	n.crypto.DHPublicKey = nil
	n.crypto.GenerateDHCurve()
	DHPrivateKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when starting DH key exchange: %v", err)
	}
	n.crypto.DHPrivateKey = DHPrivateKey
	n.crypto.DHPublicKey = DHPrivateKey.PublicKey()
	dest := n.FindDHNextHop(&receivers)

	PreviousKeys := make([]([]byte), 1)
	PreviousKeys[0], err = x509.MarshalPKIXPublicKey(n.crypto.DHPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling local DH public key: %v", err)
	}

	upMsg := types.GroupCallDHUpward{PreviousKeys: PreviousKeys, RemainingReceivers: receivers}

	data, err := json.Marshal(&upMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DHDownward msg for %v: %v", n.crypto.RingPredecessor, err)
	}

	upTransportMsg := transport.Message{
		Type:    upMsg.Name(),
		Payload: data,
	}
	return n.Unicast(dest, upTransportMsg)
}

func StrSliceContains(slice *[]string, element string) (int, bool) {
	for index, v := range *slice {
		if v == element {
			return index, true
		}
	}
	return 0, false
}

func (n *node) FindDHNextHop(receivers *[]string) string {
	neighbors := n.routingTable.neighbors(n.GetAddress())
	for _, neighbor := range neighbors {
		if index, ok := StrSliceContains(receivers, neighbor); ok {
			*receivers = append((*receivers)[:index], (*receivers)[index+1:]...)
			return neighbor
		}
	}
	*receivers = (*receivers)[1:]
	return (*receivers)[0]
}

func EndDHUpwardStep(n *node, message *types.GroupCallDHUpward) error {
	remotePK, err := x509.ParsePKIXPublicKey(message.PreviousKeys[len(message.PreviousKeys)-1])
	if err != nil {
		return xerrors.Errorf("error when parsing remote DH PK: %v", err)
	}
	remotePubKey, ok := remotePK.(*ecdh.PublicKey)
	if !ok {
		return xerrors.Errorf("error when casting remote DH PK: type %T", remotePK)
	}

	curve := remotePubKey.Curve()
	n.crypto.DHCurve = curve
	sharedSecret, err := n.crypto.DHUpwardStepNewValue(curve, remotePubKey)
	if err != nil {
		return err
	}

	n.crypto.DHSharedSecret = sharedSecret

	downwardKeys := make([]([]byte), 1)
	localPK, err := x509.MarshalPKIXPublicKey(n.crypto.DHPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling local DH PK: %v", err)
	}
	downwardKeys[0] = localPK

	for index := range message.PreviousKeys {
		if index == len(message.PreviousKeys)-1 {
			break
		}
		val := message.PreviousKeys[index]
		remotePK, err := x509.ParsePKIXPublicKey(val)
		if err != nil {
			return xerrors.Errorf("error when parsing remote DH PK: %v", err)
		}
		remotePubKey, ok := remotePK.(*ecdh.PublicKey)
		if !ok {
			return xerrors.Errorf("error when casting remote DH PK: type %t", remotePK)
		}
		DHProductKey, err := n.crypto.DHPrivateKey.ECDH(remotePubKey)
		if err != nil {
			return xerrors.Errorf("error when generating the product of the DH keys: %v", err)
		}
		DHProductPublicKey, err := n.crypto.DHCurve.NewPublicKey(DHProductKey)
		if err != nil {
			return xerrors.Errorf("error when casting DH key bytes to PrivateKey: %v", err)
		}
		localPK, err := x509.MarshalPKIXPublicKey(DHProductPublicKey)
		if err != nil {
			return xerrors.Errorf("error when marshaling remote DH PK: %v", err)
		}

		downwardKeys = append(downwardKeys, localPK)
	}

	upMsg := types.GroupCallDHDownward{PreviousKeys: downwardKeys}

	data, err := json.Marshal(&upMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DHDownward msg for %v: %v", n.crypto.RingPredecessor, err)
	}

	upTransportMsg := transport.Message{
		Type:    upMsg.Name(),
		Payload: data,
	}
	return n.Unicast(n.crypto.RingPredecessor, upTransportMsg)
}

func (n *node) ExecGroupCallDHUpward(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.GroupCallDHUpward)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	n.crypto.RingPredecessor = packet.Header.Source

	if len(message.RemainingReceivers) == 0 {
		//end of upward step
		return EndDHUpwardStep(n, message)
	}

	dest := n.FindDHNextHop(&message.RemainingReceivers)

	remotePK, err := x509.ParsePKIXPublicKey(message.PreviousKeys[len(message.PreviousKeys)-1])
	if err != nil {
		return xerrors.Errorf("error when parsing remote DH PK: %v", err)
	}
	remotePubKey, ok := remotePK.(*ecdh.PublicKey)
	if !ok {
		return xerrors.Errorf("error when casting remote DH PK: type %t", remotePK)
	}

	curve := remotePubKey.Curve()
	n.crypto.DHCurve = curve
	newPublicKey, err := n.crypto.DHUpwardStepNewValue(curve, remotePubKey)
	if err != nil {
		return err
	}

	newPK, err := x509.MarshalPKIXPublicKey(newPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling local DH PK: %v", err)
	}

	message.PreviousKeys = append(message.PreviousKeys, newPK)

	upMsg := types.GroupCallDHUpward{
		PreviousKeys:       message.PreviousKeys,
		RemainingReceivers: message.RemainingReceivers,
	}

	data, err := json.Marshal(&upMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DHDownward msg for %v: %v", n.crypto.RingPredecessor, err)
	}

	upTransportMsg := transport.Message{
		Type:    upMsg.Name(),
		Payload: data,
	}
	return n.Unicast(dest, upTransportMsg)
}

func (n *node) ExecGroupCallDHDownward(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.GroupCallDHDownward)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	downKeys, err := n.crypto.DHDownwardStepGetSecret(n.crypto.DHCurve, &message.PreviousKeys)
	if err != nil {
		return err
	}

	if len(downKeys) == 0 {
		//End of the downward step
		return nil
	}

	downMsg := types.GroupCallDHDownward{PreviousKeys: downKeys}

	data, err := json.Marshal(&downMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DHDownward msg for %v: %v", n.crypto.RingPredecessor, err)
	}

	downTransportMsg := transport.Message{
		Type:    downMsg.Name(),
		Payload: data,
	}

	return n.Unicast(n.crypto.RingPredecessor, downTransportMsg)
}
