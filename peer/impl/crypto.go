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
	KeyPair  *rsa.PrivateKey
	KnownPKs StrStrMap

	DHCurve        ecdh.Curve
	DHPrivateKey   *ecdh.PrivateKey
	DHPublicKey    *ecdh.PublicKey
	DHSharedSecret *ecdh.PublicKey

	DHIsLeader       bool
	DHchannels       map[string](chan struct{})
	DHInitSecrets    map[string](*ecdh.PrivateKey)
	DHPartialSecrets map[string](*ecdh.PublicKey)
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
		multicastReceivers[s] = struct{}{}
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
	for i, dest := range receivers {
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
					return xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
				}
				keyToSend, err = n.crypto.DHCurve.NewPublicKey(newKeyToSend)
				if err != nil {
					return xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
				}
			}
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

func (n *node) GroupCallRemove(member string) error {
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
	for dest := range n.crypto.DHPartialSecrets {
		var keyToSend = n.crypto.DHPartialSecrets[n.GetAddress()]
		for j, k := range n.crypto.DHInitSecrets {
			if dest == j {
				continue
			}
			newKeyToSend, err := k.ECDH(keyToSend)
			if err != nil {
				return xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
			}
			keyToSend, err = n.crypto.DHCurve.NewPublicKey(newKeyToSend)
			if err != nil {
				return xerrors.Errorf("error in DH key exchange when generating partial shared secret for %v: %v", dest, err)
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

func (n *node) GroupCallAdd(member string) error {
	if !n.crypto.DHIsLeader {
		return nil
	}

	initMsg := types.GroupCallDHIndividual{RemoteKey: n.crypto.DHPublicKey.Bytes()}
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

	n.Unicast(member, initTransportMsg)

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
	n.Unicast(member, transportMsg)

	//Now we send the key to the new member
	newMemberSecret, ok := n.crypto.DHInitSecrets[member]
	if !ok {
		return xerrors.Errorf("error when retrieving new member (%v)'s shared secret", member)
	}
	newSharedSecretBytes, err := newMemberSecret.ECDH(n.crypto.DHPublicKey)
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
		newPartialSecretKeyBytes, err = newMemberSecret.ECDH(key)
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
		n.Unicast(s, transportMsg)
	}

	return nil
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
	n.crypto.DHSharedSecret, err = n.crypto.DHCurve.NewPublicKey(sharedSecret)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating secret: %v", err)
	}
	localPublicKeyBytes, err := x509.MarshalPKIXPublicKey(n.crypto.DHPublicKey)
	if err != nil {
		return xerrors.Errorf("error when marshaling DH init answer from %v to %v: %v", n.GetAddress(), packet.Header.Source, err)
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
	n.Unicast(packet.Header.Source, initTransportMsg)
	return nil
}

func (n *node) ExecGroupCallDHSharedSecret(msg types.Message, packet transport.Packet) error {
	message, ok := msg.(*types.GroupCallDHSharedSecret)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	sharedSecretSK, err := n.crypto.DHCurve.NewPrivateKey(n.crypto.DHSharedSecret.Bytes())
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
