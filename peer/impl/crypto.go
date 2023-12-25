// HOW TO USE
// when a group call starts, the initiator should call n.StartDHKeyExchange(members)
// with members a slice containing the addresses of all other members of the call
// (all members except the initiator)
// When a peer is added to the call, the initiator should call n.GroupCallAdd(member)
// with member being the address of the peer to add
// When a peer is to me removed, the initiator should call n.GroupCallRemove(member)
// with member being the address of the peer to remove
// The addition/removal functions can be called on every members of the call,
// if the node isn't the initiator the function will not do anything
// but if possible, do only call it on the initiator
// When a call ends from the peer's PoV, this peer should call n.GroupCallEnd()
// n.crypto.GenerateKeyPair() generates a public ID
// n.crypto.AddPublicKey(peer, key) sets the knowledge that peer's ID is key
// n.crypto.RemovePublicKey(peer) removes the knowledge of peer's ID
// n.crypto.VerifyPK(peer, key) returns whether peer's known ID is key or not
// n.crypto.EncryptOneToOne(msg, key) encrypts a One to One message
// with the remote public key "key" (max msg bytes size: 446)
// n.crypto.DecryptOneToOne(msg) decrypts the msg with the local private key
// n.crypto.EncryptDH(msg) encrypts the msg with the DH shared secret
// n.crypto.DecryptDH(msg) decrypts the msg with the DH shared secret

// Group DH is based on "Elliptic Curve Based Dynamic Contributory Group Key Agreement Protocol
// For Secure Group Communication Over Ad-hoc Networks" by Naresh et al.

package impl

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"strconv"
	"strings"
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
	KeyPair  *rsa.PrivateKey
	KnownPKs StrStrMap

	DHCurve        ecdh.Curve
	DHPrivateKey   *ecdh.PrivateKey
	DHPublicKey    *ecdh.PublicKey
	DHSharedSecret *ecdh.PublicKey

	DHIsLeader             bool
	DHSharedPersonalSecret *ecdh.PublicKey
	DHchannels             map[string](chan struct{})
	DHInitSecrets          map[string](*ecdh.PrivateKey)
	DHPartialSecrets       map[string](*ecdh.PublicKey)
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

func (c *Crypto) Sign(key, packet []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(key)
	if err != nil {
		return nil, xerrors.Errorf("error when hashing msg: %v", err)
	}
	_, err = hash.Write(packet)
	if err != nil {
		return nil, xerrors.Errorf("error when hashing msg: %v", err)
	}
	hashSum := hash.Sum(nil)
	return rsa.SignPSS(rand.Reader, c.KeyPair, crypto.SHA256, hashSum, nil)
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

func (c *Crypto) EncryptOneToOnePkt(pkt *transport.Packet, key *rsa.PublicKey) (*transport.Packet, error) {
	marshaledPkt, err := pkt.Marshal()
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling packet for O2O encryption: %v", err)
	}
	randomKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("error when generating random key for O2O encryption: %v", err)
	}

	encryptedKey, err := c.EncryptOneToOne(randomKey.PublicKey().Bytes(), key)
	if err != nil {
		return nil, xerrors.Errorf("error when encrypting packet for O2O encryption: %v", err)
	}

	ciph, err := aes.NewCipher(randomKey.PublicKey().Bytes())
	if err != nil {
		return nil, xerrors.Errorf("error encrypting packet for O2O encryption: %v", err)
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, xerrors.Errorf("error encrypting packet for O2O encryption: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, xerrors.Errorf("error encrypting packet for O2O encryption: %v", err)
	}

	encryptedPkt := gcm.Seal(nonce, nonce, marshaledPkt, nil)

	pkBytes, err := x509.MarshalPKIXPublicKey(&c.KeyPair.PublicKey)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling local PK: %v", err)
	}

	sig, err := c.Sign(encryptedKey, encryptedPkt)
	if err != nil {
		return nil, xerrors.Errorf("error when signing packet in O2O pkt encryption: %v", err)
	}

	encryptedMsg := types.O2OEncryptedPkt{Packet: encryptedPkt, Key: encryptedKey, RemoteKey: pkBytes, Signature: sig}
	data, err := json.Marshal(&encryptedMsg)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling encrypted packet for O2O encryption: %v", err)
	}
	transpMsg := transport.Message{Payload: data, Type: encryptedMsg.Name()}
	header := pkt.Header.Copy()
	packet := transport.Packet{Header: &header, Msg: &transpMsg}
	return &packet, nil
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

func (c *Crypto) EncryptDHPkt(pkt *transport.Packet) (*transport.Message, error) {
	marshaledPkt, err := pkt.Marshal()
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling packet in DH pkt encryption: %v", err)
	}

	pkA, err := x509.MarshalPKIXPublicKey(&c.KeyPair.PublicKey)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling local PK in DH pkt encryption: %v", err)
	}

	encryptedPkt, err := c.EncryptDH(marshaledPkt)
	if err != nil {
		return nil, xerrors.Errorf("error when encrypting packet in DH pkt encryption: %v", err)
	}

	sig, err := c.Sign(nil, encryptedPkt)
	if err != nil {
		return nil, xerrors.Errorf("error when signing packet in DH pkt encryption: %v", err)
	}

	encryptedMsg := types.DHEncryptedPkt{Packet: encryptedPkt, RemoteKey: pkA, Signature: sig}
	data, err := json.Marshal(&encryptedMsg)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling msg in DH pkt encryption: %v", err)
	}

	transpMsg := transport.Message{Payload: data, Type: encryptedMsg.Name()}
	return &transpMsg, nil
}

func ConstructKeyToSend(n *node, dest string) (*ecdh.PublicKey, error) {
	var keyToSend *ecdh.PublicKey
	for j, k := range n.crypto.DHInitSecrets {
		if dest == j {
			continue
		}
		if keyToSend == nil {
			keyToSend = k.PublicKey()
		} else {
			newKeyToSend, err := k.ECDH(keyToSend)
			if err != nil {
				return nil, xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
			}
			keyToSend, err = n.crypto.DHCurve.NewPublicKey(newKeyToSend)
			if err != nil {
				return nil, xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
			}
		}
	}
	return keyToSend, nil
}

// Auxiliary function for StartDHKeyExchange sending the partial secrets to all other call members
func SendPartialSecrets(n *node, receivers []string) error {
	for i, dest := range receivers {
		keyToSend, err := ConstructKeyToSend(n, dest)
		if err != nil {
			return err
		}
		if i == 0 {
			sharedSecretBytes, err := n.crypto.DHInitSecrets[dest].ECDH(keyToSend)
			if err != nil {
				return xerrors.Errorf("error when generating shared secret bytes: %v", err)
			}
			n.crypto.DHSharedSecret, err = n.crypto.DHCurve.NewPublicKey(sharedSecretBytes)
			if err != nil {
				return xerrors.Errorf("error when generating shared secret: %v", err)
			}
		}
		n.crypto.DHPartialSecrets[dest] = keyToSend
		localKey, err := x509.MarshalPKIXPublicKey(keyToSend)
		if err != nil {
			return xerrors.Errorf("error in DH key exchange when marshaling partial shared secret for %v: %v", dest, err)
		}
		ssMsg := types.GroupCallDHSharedSecret{RemoteKey: localKey}
		data, err := json.Marshal(&ssMsg)

		if err != nil {
			return xerrors.Errorf("error when marshaling DH init msg: %v", err)
		}

		ssTransportMsg := transport.Message{
			Type:    ssMsg.Name(),
			Payload: data,
		}

		err = n.Unicast(dest, ssTransportMsg)
		if err != nil {
			return xerrors.Errorf("error when marshaling DH init msg: %v", err)
		}
	}
	return nil
}

func (n *node) StartDHKeyExchange(receivers []string) error {
	n.crypto.DHIsLeader = true
	n.crypto.DHInitSecrets = make(map[string](*ecdh.PrivateKey))
	n.crypto.DHchannels = make(map[string]chan struct{})
	n.crypto.DHPartialSecrets = make(map[string]*ecdh.PublicKey)
	n.crypto.GenerateDHCurve()
	DHPrivateKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when starting DH key exchange: %v", err)
	}
	n.crypto.DHPrivateKey = DHPrivateKey
	n.crypto.DHPublicKey = DHPrivateKey.PublicKey()
	multicastReceivers := make(map[string]struct{})
	for _, s := range receivers {
		if IsAddress(s) {
			multicastReceivers[s] = struct{}{}
		}
	}

	localPKBytes, err := x509.MarshalPKIXPublicKey(n.crypto.DHPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling initiator PK: %v", err)
	}

	initMsg := types.GroupCallDHIndividual{RemoteKey: localPKBytes}
	data, err := json.Marshal(&initMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DH init msg: %v", err)
	}

	initTransportMsg := transport.Message{
		Type:    initMsg.Name(),
		Payload: data,
	}

	var wg sync.WaitGroup
	for _, s := range receivers {
		n.crypto.DHchannels[s] = make(chan struct{})
		wg.Add(1)
		go func(c <-chan struct{}) {
			defer wg.Done()
			for range c {
				return
			}
		}(n.crypto.DHchannels[s])
	}

	err = n.Multicast(initTransportMsg, multicastReceivers)
	if err != nil {
		return xerrors.Errorf("error in DH key exchange init multicast: %v", err)
	}

	wg.Wait()

	return SendPartialSecrets(n, receivers)
}

func SendPartialSecretsRemoveBuildKeyToSend(n *node, dest string) (*ecdh.PublicKey, error) {
	var keyToSend = n.crypto.DHPartialSecrets[n.GetAddress()]
	for j, k := range n.crypto.DHInitSecrets {
		if dest == j {
			continue
		}
		newKeyToSend, err := k.ECDH(keyToSend)
		if err != nil {
			return nil, xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
		}
		keyToSend, err = n.crypto.DHCurve.NewPublicKey(newKeyToSend)
		if err != nil {
			return nil, xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
		}
	}
	return keyToSend, nil
}

func SendPartialSecretsRemove(n *node, member string) error {
	newSharedSecretSet := false
	for dest := range n.crypto.DHPartialSecrets {
		if dest == n.GetAddress() {
			continue
		}
		keyToSend, err := SendPartialSecretsRemoveBuildKeyToSend(n, dest)
		if err != nil {
			return err
		}
		n.crypto.DHPartialSecrets[dest] = keyToSend
		localKey, err := x509.MarshalPKIXPublicKey(keyToSend)
		if err != nil {
			return xerrors.Errorf("error in DH key exchange when marshaling partial shared secret for %v: %v", dest, err)
		}
		ssMsg := types.GroupCallDHSharedSecret{RemoteKey: localKey}
		data, err := json.Marshal(&ssMsg)

		if err != nil {
			return xerrors.Errorf("error when marshaling DH init msg: %v", err)
		}

		ssTransportMsg := transport.Message{
			Type:    ssMsg.Name(),
			Payload: data,
		}

		err = n.Unicast(dest, ssTransportMsg)
		if err != nil {
			return xerrors.Errorf("error when marshaling DH init msg: %v", err)
		}
		if !newSharedSecretSet {
			newSS, err := n.crypto.DHInitSecrets[dest].ECDH(keyToSend)
			if err != nil {
				return xerrors.Errorf("error when computing new DH SS bytes for removal of %v: %v", member, err)
			}
			n.crypto.DHSharedSecret, err = n.crypto.DHCurve.NewPublicKey(newSS)
			if err != nil {
				return xerrors.Errorf("error when computing new DH SS for removal of %v: %v", member, err)
			}
			newSharedSecretSet = true
		}
	}
	return nil
}

func (n *node) GroupCallRemove(member string) error {
	if !IsAddress(member) {
		return xerrors.Errorf("error in GoupCallRemove: member isn't an IP address with port")
	}
	if !n.crypto.DHIsLeader {
		return nil
	}
	//If member = leader: must restart the exchange from a new leader, the leader should chose a new one
	//Otherwise, recompute the partial secrets without member's secret and send them
	if member == n.conf.Socket.GetAddress() {
		return nil
	}
	newKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when generating new key to remove member %v: %v", member, err)
	}
	existingOffset, ok := n.crypto.DHPartialSecrets[n.GetAddress()]
	if !ok {
		n.crypto.DHPartialSecrets[n.GetAddress()] = newKey.PublicKey()
	} else {
		newOffset, err := newKey.ECDH(existingOffset)
		if err != nil {
			return xerrors.Errorf("error when generating new local PK bytes to remove member %v: %v", member, err)
		}
		n.crypto.DHPartialSecrets[n.GetAddress()], err = n.crypto.DHCurve.NewPublicKey(newOffset)
		if err != nil {
			return xerrors.Errorf("error when generating new local PK to remove member %v: %v", member, err)
		}
	}

	delete(n.crypto.DHInitSecrets, member)
	delete(n.crypto.DHPartialSecrets, member)
	return SendPartialSecretsRemove(n, member)
}

func SendPartialSecretsInAddition(n *node, member string, newKey *ecdh.PrivateKey) error {

	//Now we send the key to the new member
	newMemberSecret, ok := n.crypto.DHInitSecrets[member]
	if !ok {
		return xerrors.Errorf("error when retrieving new member (%v)'s shared secret", member)
	}
	newSharedSecretBytes, err := newMemberSecret.ECDH(n.crypto.DHSharedSecret)
	if err != nil {
		return xerrors.Errorf("error when generating new shared PK bytes to add member %v: %v", member, err)
	}
	n.crypto.DHSharedSecret, err = n.crypto.DHCurve.NewPublicKey(newSharedSecretBytes)
	if err != nil {
		return xerrors.Errorf("error when generating new shared PK to add member %v: %v", member, err)
	}

	for s, key := range n.crypto.DHPartialSecrets {
		if s == n.GetAddress() {
			continue
		}
		newPartialSecretKeyBytes, err := newKey.ECDH(key)
		if err != nil {
			return xerrors.Errorf("error when generating new patial secret bytes for %v to add member %v: %v", s, member, err)
		}
		newPartialSecretKey, err := n.crypto.DHCurve.NewPublicKey(newPartialSecretKeyBytes)
		if err != nil {
			return xerrors.Errorf("error when generating new partial secret for %v to add member %v: %v", s, member, err)
		}
		newPartialSecretKeyBytes, err = newMemberSecret.ECDH(newPartialSecretKey)
		if err != nil {
			return xerrors.Errorf("error when generating new patial secret bytes for %v to add member %v: %v", s, member, err)
		}
		newPartialSecretKey, err = n.crypto.DHCurve.NewPublicKey(newPartialSecretKeyBytes)
		if err != nil {
			return xerrors.Errorf("error when generating new partial secret for %v to add member %v: %v", s, member, err)
		}
		n.crypto.DHPartialSecrets[s] = newPartialSecretKey
		newPartialSecretKeyMarshaled, err := x509.MarshalPKIXPublicKey(newPartialSecretKey)
		if err != nil {
			return xerrors.Errorf("error when marshaling partial key for %v to add %v: %v", s, member, err)
		}
		msg := types.GroupCallDHSharedSecret{RemoteKey: newPartialSecretKeyMarshaled}
		data, err := json.Marshal(&msg)
		if err != nil {
			return xerrors.Errorf("error when marshaling DH addition msg of %v for %v: %v", member, s, err)
		}

		transportMsg := transport.Message{
			Type:    msg.Name(),
			Payload: data,
		}
		err = n.Unicast(s, transportMsg)
		if err != nil {
			return xerrors.Errorf("error when unicasting new partial secret to %v for adding member %v: %v", s, member, err)
		}
	}
	return nil
}

func (n *node) GroupCallAdd(member string) error {
	if !IsAddress(member) {
		return xerrors.Errorf("error in GoupCallAdd: member isn't an IP address with port")
	}
	if !n.crypto.DHIsLeader {
		return nil
	}

	localPKBytes, err := x509.MarshalPKIXPublicKey(n.crypto.DHPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling local DH PK to add member %v: %v", member, err)
	}

	initMsg := types.GroupCallDHIndividual{RemoteKey: localPKBytes}
	data, err := json.Marshal(&initMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DH init msg: %v", err)
	}

	initTransportMsg := transport.Message{
		Type:    initMsg.Name(),
		Payload: data,
	}

	var wg sync.WaitGroup
	n.crypto.DHchannels[member] = make(chan struct{})
	wg.Add(1)
	go func(c <-chan struct{}) {
		defer wg.Done()
		for range c {
			return
		}
	}(n.crypto.DHchannels[member])

	err = n.Unicast(member, initTransportMsg)
	if err != nil {
		return xerrors.Errorf("error when unicasting individual DH to additional member %v: %v", member, err)
	}

	wg.Wait()

	newKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when generating new key to add member %v: %v", member, err)
	}
	existingOffset, ok := n.crypto.DHPartialSecrets[n.GetAddress()]
	if !ok {
		n.crypto.DHPartialSecrets[n.GetAddress()] = newKey.PublicKey()
	} else {
		newOffset, err := newKey.ECDH(existingOffset)
		if err != nil {
			return xerrors.Errorf("error when generating new local PK bytes to add member %v: %v", member, err)
		}
		n.crypto.DHPartialSecrets[n.GetAddress()], err = n.crypto.DHCurve.NewPublicKey(newOffset)
		if err != nil {
			return xerrors.Errorf("error when generating new local PK to add member %v: %v", member, err)
		}
	}

	newSSKey, err := newKey.ECDH(n.crypto.DHSharedSecret)
	if err != nil {
		return xerrors.Errorf("error when generating new SS bytes to add member %v: %v", member, err)
	}
	n.crypto.DHSharedSecret, err = n.crypto.DHCurve.NewPublicKey(newSSKey)
	if err != nil {
		return xerrors.Errorf("error when generating new SS to add member %v: %v", member, err)
	}

	newPartialSecretKeyMarshaled, err := x509.MarshalPKIXPublicKey(n.crypto.DHSharedSecret)
	if err != nil {
		return xerrors.Errorf("error when marshaling partial key for %v to add %v: %v", member, member, err)
	}
	msg := types.GroupCallDHSharedSecret{RemoteKey: newPartialSecretKeyMarshaled}
	data, err = json.Marshal(&msg)
	if err != nil {
		return xerrors.Errorf("error when marshaling DH addition msg of %v for %v: %v", member, member, err)
	}

	transportMsg := transport.Message{
		Type:    msg.Name(),
		Payload: data,
	}
	err = n.Unicast(member, transportMsg)
	if err != nil {
		return xerrors.Errorf("error when unicasting partial secret to additional member %v: %v", member, err)
	}

	return SendPartialSecretsInAddition(n, member, newKey)
}

func (c *Crypto) GroupCallEnd() {
	c.DHSharedSecret = nil
	c.DHPrivateKey = nil
	c.DHPublicKey = nil
	c.DHIsLeader = false
	for s, ch := range c.DHchannels {
		close(ch)
		delete(c.DHchannels, s)
	}
	for s := range c.DHInitSecrets {
		delete(c.DHchannels, s)
	}
	for s := range c.DHPartialSecrets {
		delete(c.DHPartialSecrets, s)
	}
}

func (n *node) ExecGroupCallDHIndividual(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.GroupCallDHIndividual)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}
	remoteK, err := x509.ParsePKIXPublicKey(message.RemoteKey)
	if err != nil {
		return xerrors.Errorf("error when parsing remote DH individual PK: %v", err)
	}
	remoteKey, ok := remoteK.(*ecdh.PublicKey)
	if !ok {
		return xerrors.Errorf("error when casting remote DH individual PK: type %T", remoteK)
	}
	if n.crypto.DHIsLeader {
		sharedSecretBytes, err := n.crypto.DHPrivateKey.ECDH(remoteKey)
		if err != nil {
			return xerrors.Errorf("error in individual DH key exchange when generating secret bytes: %v", err)
		}
		sharedSecret, err := n.crypto.DHCurve.NewPrivateKey(sharedSecretBytes)
		if err != nil {
			return xerrors.Errorf("error in individual DH key exchange when generating secret: %v", err)
		}
		n.crypto.DHInitSecrets[packet.Header.Source] = sharedSecret
		n.crypto.DHchannels[packet.Header.Source] <- struct{}{}
		close(n.crypto.DHchannels[packet.Header.Source])
		delete(n.crypto.DHchannels, packet.Header.Source)
		return nil
	}
	n.crypto.DHCurve = remoteKey.Curve()
	n.crypto.DHPrivateKey, err = remoteKey.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating key: %v", err)
	}
	n.crypto.DHPublicKey = n.crypto.DHPrivateKey.PublicKey()
	sharedSecret, err := n.crypto.DHPrivateKey.ECDH(remoteKey)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating secret bytes: %v", err)
	}
	n.crypto.DHSharedPersonalSecret, err = n.crypto.DHCurve.NewPublicKey(sharedSecret)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating secret: %v", err)
	}
	localPublicKeyBytes, err := x509.MarshalPKIXPublicKey(n.crypto.DHPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling DH init answer from %v to %v: %v",
			n.GetAddress(),
			packet.Header.Source,
			err,
		)
	}
	initMsg := types.GroupCallDHIndividual{RemoteKey: localPublicKeyBytes}
	data, err := json.Marshal(&initMsg)

	if err != nil {
		return xerrors.Errorf("error when marshaling DH init msg: %v", err)
	}

	initTransportMsg := transport.Message{
		Type:    initMsg.Name(),
		Payload: data,
	}
	err = n.Unicast(packet.Header.Source, initTransportMsg)
	if err != nil {
		return xerrors.Errorf("error when unicasting DH exchange answer from %v to %v: %v",
			n.GetAddress(),
			packet.Header.Source,
			err,
		)
	}
	return nil
}

func (n *node) ExecGroupCallDHSharedSecret(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.GroupCallDHSharedSecret)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	sharedSecretSK, err := n.crypto.DHCurve.NewPrivateKey(n.crypto.DHSharedPersonalSecret.Bytes())
	if err != nil {
		return xerrors.Errorf("error when casting shared secret to private key: %v", err)
	}
	remoteK, err := x509.ParsePKIXPublicKey(message.RemoteKey)
	if err != nil {
		return xerrors.Errorf("error when parsing shared secret: %v", err)
	}
	remoteKey, ok := remoteK.(*ecdh.PublicKey)
	if !ok {
		return xerrors.Errorf("error when casting remoteKey to public key")
	}
	finalSecretBytes, err := sharedSecretSK.ECDH(remoteKey)
	if err != nil {
		return xerrors.Errorf("error when generating final shared secret: %v", err)
	}
	n.crypto.DHSharedSecret, err = n.crypto.DHCurve.NewPublicKey(finalSecretBytes)
	if err != nil {
		return xerrors.Errorf("error when creating shared secret: %v", err)
	}
	return nil
}

func IsAddress(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return false
	}
	port := parts[1]
	addr := parts[0]
	addrParts := strings.Split(addr, ".")
	if len(addrParts) != 4 {
		return false
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	for _, part := range addrParts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func (n *node) ExecO2OEncryptedPkt(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.O2OEncryptedPkt)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	hash := sha256.New()
	_, err := hash.Write(message.Key)
	if err != nil {
		return xerrors.Errorf("error when hashing msg: %v", err)
	}
	_, err = hash.Write(message.Packet)
	if err != nil {
		return xerrors.Errorf("error when hashing msg: %v", err)
	}
	hashSum := hash.Sum(nil)

	remoteK, err := x509.ParsePKIXPublicKey(message.RemoteKey)
	if err != nil {
		return xerrors.Errorf("error when parsing remote PK: %v", err)
	}
	remoteKey, ok := remoteK.(*rsa.PublicKey)
	if !ok {
		return xerrors.Errorf("error when casting remote PK to rsa.PK")
	}

	err = rsa.VerifyPSS(remoteKey, crypto.SHA256, hashSum, message.Signature, nil)
	if err != nil {
		return xerrors.Errorf("signature mismatch: %v", err)
	}

	dectyptedKey, err := n.crypto.DecryptOneToOne(message.Key)
	if err != nil {
		return xerrors.Errorf("error decrypting O2O encrypted pkt: %v", err)
	}

	ciph, err := aes.NewCipher(dectyptedKey)
	if err != nil {
		return xerrors.Errorf("error decrypting msg for O2O encryption: %v", err)
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return xerrors.Errorf("error decrypting msg for O2O encryption: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(message.Packet) < nonceSize {
		return xerrors.Errorf("error decrypting msg for O2O encryption: msg size is smaller than nonce")
	}

	nonce, ciphertext := message.Packet[:nonceSize], message.Packet[nonceSize:]
	decryptedPkt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return xerrors.Errorf("error decrypting msg for O2O encryption: %v", err)
	}

	var pkt transport.Packet
	err = pkt.Unmarshal(decryptedPkt)
	if err != nil {
		return xerrors.Errorf("error unmarshaling O2O encrypted packet: %v", err)
	}
	n.processPacket(pkt)
	return nil
}

func (n *node) ExecDHEncryptedPkt(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.DHEncryptedPkt)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	dectyptedPkt, err := n.crypto.DecryptDH(message.Packet)
	if err != nil {
		return xerrors.Errorf("error decrypting DH encrypted pkt: %v", err)
	}
	var pkt transport.Packet
	err = pkt.Unmarshal(dectyptedPkt)
	if err != nil {
		return xerrors.Errorf("error unmarshaling DH encrypted packet: %v", err)
	}
	n.processPacket(pkt)
	return nil
}
