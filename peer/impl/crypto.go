// HOW TO USE

// Note that when creating a node n, the parameter n.crypto.PublicID should be set to an hard to forge unique ID
// (ex a phone number that we assumed to be verified before entering the node creation system)

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
// n.crypto.EncryptOneToOneMsg(pkt, key) encrypts the pkt with the remote PK key
// then packs it in an O2OEncryptedPkt message (works for any size)
// n.crypto.EncryptDHMsg(pkt) encrypts the pkt with the DH shared secret and
// returns a transport.Message (DHEncryptedPkt type)

// Group DH is based on "Elliptic Curve Based Dynamic Contributory Group Key Agreement Protocol
// For Secure Group Communication Over Ad-hoc Networks" by Naresh et al.

package impl

import (
	"bytes"
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
	"time"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

type StrBytesPair struct {
	Str   string
	Bytes []byte
}

type StrStrMap struct {
	Mutex sync.Mutex
	Map   map[string]StrBytesPair
}

func (m *StrStrMap) Get(peer string) (StrBytesPair, bool) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	pubID, ok := m.Map[peer]
	return pubID, ok
}

type StrChanMap struct {
	Mutex sync.Mutex
	Map   map[string](chan struct{})
}

func (m *StrChanMap) Add(s string) {
	m.Mutex.Lock()
	m.Map[s] = make(chan struct{})
	m.Mutex.Unlock()
}

func (m *StrChanMap) Delete(s string) {
	m.Mutex.Lock()
	close(m.Map[s])
	delete(m.Map, s)
	m.Mutex.Unlock()
}

func (m *StrChanMap) Get(s string) chan struct{} {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	return m.Map[s]
}

func (m *StrChanMap) SafeGet(s string) (chan struct{}, bool) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	v, ok := m.Map[s]
	return v, ok
}

type DHPrivateKey struct {
	Mutex sync.Mutex
	Key   *ecdh.PrivateKey
}

func (k *DHPrivateKey) Set(key *ecdh.PrivateKey) {
	k.Mutex.Lock()
	k.Key = key
	k.Mutex.Unlock()
}

func (k *DHPrivateKey) Get() *ecdh.PrivateKey {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	return k.Key
}

func (k *DHPrivateKey) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	b, err := k.Key.ECDH(remote)
	return b, err
}

func (k *DHPrivateKey) Bytes() []byte {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	return k.Key.Bytes()
}

type DHPublicKey struct {
	Mutex sync.Mutex
	Key   *ecdh.PublicKey
}

func (k *DHPublicKey) Set(key *ecdh.PublicKey) {
	k.Mutex.Lock()
	k.Key = key
	k.Mutex.Unlock()
}

func (k *DHPublicKey) Get() *ecdh.PublicKey {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	return k.Key
}

func (k *DHPublicKey) Equal(remote *ecdh.PublicKey) bool {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	if k.Key == nil {
		return remote == nil
	}
	return k.Key.Equal(remote)
}

func (k *DHPublicKey) Bytes() []byte {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	return k.Key.Bytes()
}

func (k *DHPublicKey) ECDH(key *ecdh.PrivateKey) ([]byte, error) {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	v, err := key.ECDH(k.Key)
	return v, err
}

func (k *DHPublicKey) Marshal() ([]byte, error) {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()
	v, err := x509.MarshalPKIXPublicKey(k.Key)
	return v, err
}

type DHCurve struct {
	Mutex sync.Mutex
	Curve ecdh.Curve
}

func (c *DHCurve) Set(curve ecdh.Curve) {
	c.Mutex.Lock()
	c.Curve = curve
	c.Mutex.Unlock()
}

func (c *DHCurve) Get() ecdh.Curve {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	return c.Curve
}

func (c *DHCurve) NewPrivateKey(key []byte) (*ecdh.PrivateKey, error) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.Curve == nil {
		return nil, xerrors.Errorf("curve is nil")
	}
	v, err := c.Curve.NewPrivateKey(key)
	return v, err
}

func (c *DHCurve) NewPublicKey(key []byte) (*ecdh.PublicKey, error) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.Curve == nil {
		return nil, xerrors.Errorf("curve is nil")
	}
	v, err := c.Curve.NewPublicKey(key)
	return v, err
}

func (c *DHCurve) GenerateKey(reader io.Reader) (*ecdh.PrivateKey, error) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.Curve == nil {
		return nil, xerrors.Errorf("curve is nil")
	}
	v, err := c.Curve.GenerateKey(reader)
	return v, err
}

type MutexBool struct {
	Mutex sync.Mutex
	Bool  bool
}

func (b *MutexBool) Set(v bool) {
	b.Mutex.Lock()
	b.Bool = v
	b.Mutex.Unlock()
}

func (b *MutexBool) Get() bool {
	b.Mutex.Lock()
	defer b.Mutex.Unlock()
	return b.Bool
}

type Crypto struct {
	PublicID string
	KeyPair  *rsa.PrivateKey
	KnownPKs StrStrMap

	DHCurve        DHCurve
	DHPrivateKey   DHPrivateKey
	DHPublicKey    DHPublicKey
	DHSharedSecret DHPublicKey

	DHIsLeader             MutexBool
	DHSharedPersonalSecret DHPublicKey
	DHchannels             StrChanMap
	DHInitSecrets          map[string](*ecdh.PrivateKey)
	DHPartialSecrets       map[string](*ecdh.PublicKey)
}

func (n *node) CreateCallMembers() map[string]struct{} {
	callMembers := make(map[string]struct{})
	for s := range n.crypto.DHPartialSecrets {
		callMembers[s] = struct{}{}
	}
	callMembers[n.GetAddress()] = struct{}{}
	return callMembers
}

func (n *node) GenerateKeyPair() error {
	//Generate a pair of RSA keys
	keyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return xerrors.Errorf("error when generating keypair: %v", err)
	}
	n.crypto.KeyPair = keyPair
	return nil
}

func (n *node) SetPublicID(id string) {
	n.crypto.PublicID = id
}

func (n *node) GetPubId() string {
	return n.crypto.PublicID
}

func (n *node) GetPK() rsa.PublicKey {
	return n.crypto.KeyPair.PublicKey
}

func (n *node) AddPublicKey(peer, pubID string, key []byte) {
	//Add a public key + id to the known IDs
	// TODO: We should put the check here for if we already have received this key
	n.crypto.KnownPKs.Mutex.Lock()
	n.crypto.KnownPKs.Map[peer] = StrBytesPair{Str: pubID, Bytes: key}
	n.crypto.KnownPKs.Mutex.Unlock()
}

func (n *node) RemovePublicKey(peer string) {
	//Forget about a public ID
	n.crypto.KnownPKs.Mutex.Lock()
	delete(n.crypto.KnownPKs.Map, peer)
	n.crypto.KnownPKs.Mutex.Unlock()
}

func (n *node) GetPeerKey(peer string) (StrBytesPair, bool) {
	//Add a public key + id to the known IDs
	n.crypto.KnownPKs.Mutex.Lock()
	defer n.crypto.KnownPKs.Mutex.Unlock()

	pair, exists := n.crypto.KnownPKs.Map[peer]
	return pair, exists
}

func (n *node) VerifyPID(peer, pubID string, key []byte) (bool, bool) {
	//Verify that a public ID matches the one stored (if any)
	n.crypto.KnownPKs.Mutex.Lock()
	defer n.crypto.KnownPKs.Mutex.Unlock()
	knownKey, ok := n.crypto.KnownPKs.Map[peer]
	return bytes.Equal(key, knownKey.Bytes) && knownKey.Str == pubID, ok
}

func (n *node) Sign(key, msgType, packet []byte) ([]byte, error) {
	//Sign the packet with the given key
	hash := sha256.New()
	_, err := hash.Write(key)
	if err != nil {
		return nil, xerrors.Errorf("error when hashing msg: %v", err)
	}
	_, err = hash.Write(msgType)
	if err != nil {
		return nil, xerrors.Errorf("error when hashing msg: %v", err)
	}
	_, err = hash.Write(packet)
	if err != nil {
		return nil, xerrors.Errorf("error when hashing msg: %v", err)
	}
	hashSum := hash.Sum(nil)
	return rsa.SignPSS(rand.Reader, n.crypto.KeyPair, crypto.SHA256, hashSum, nil)
}

func (n *node) EncryptOneToOne(msg []byte, peer string) ([]byte, error) {
	//Encrypt a message to be sent to peer with its known Public Key
	pubID, ok := n.crypto.KnownPKs.Get(peer)
	if !ok {
		//If we don't know the peer then we can't encrypt
		return nil, xerrors.Errorf("error when retrieving known Public key: unregistered")
	}

	//We retrieve the key from the bytes
	keyBytes := pubID.Bytes
	keyUnmapped, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, xerrors.Errorf("error when parsing stored key: %v", err)
	}
	key, ok := keyUnmapped.(*rsa.PublicKey)
	if !ok {
		return nil, xerrors.Errorf("error when casting stored key")
	}

	//We encrypt
	encryptedMsg, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("error when encrypting a 1to1 message: %v", err)
	}
	return encryptedMsg, nil
}

func (n *node) DecryptOneToOne(msg []byte) ([]byte, error) {
	//Decrypt the message using the local RSA private key
	decryptedMsg, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, n.crypto.KeyPair, msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("error when decrypting a 1to1 message: %v", err)
	}
	return decryptedMsg, nil
}

func (n *node) EncryptOneToOneMsg(msg *transport.Message, peer string) (*transport.Message, error) {
	//Encrypt a packet to be sent to peer with its known public key
	c := &n.crypto
	//We marshal the pakcet
	marshaledMsg, err := msg.Payload.MarshalJSON()
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling packet for O2O encryption: %v", err)
	}
	//We generate a random key to be able to encrypt any size (RSA is limited to 446)
	randomKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("error when generating random key for O2O encryption: %v", err)
	}

	//We encrypt the random key with the RSA public key of the peer
	encryptedKey, err := n.EncryptOneToOne(randomKey.PublicKey().Bytes(), peer)
	if err != nil {
		return nil, xerrors.Errorf("error when encrypting packet for O2O encryption: %v", err)
	}

	//We encrypt the packet with the random key
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

	encryptedPayload := gcm.Seal(nonce, nonce, marshaledMsg, nil)

	//We marshal the local RSA PK
	pkBytes, err := x509.MarshalPKIXPublicKey(&c.KeyPair.PublicKey)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling local PK: %v", err)
	}

	//We sign the packet
	sig, err := n.Sign(encryptedKey, []byte(msg.Type), encryptedPayload)
	if err != nil {
		return nil, xerrors.Errorf("error when signing packet in O2O pkt encryption: %v", err)
	}

	//We pack the whole in a message
	encryptedMsg := types.O2OEncryptedPkt{
		Payload:   encryptedPayload,
		Type:      msg.Type,
		Key:       encryptedKey,
		RemoteID:  c.PublicID,
		RemoteKey: pkBytes,
		Signature: sig,
	}
	data, err := json.Marshal(&encryptedMsg)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling encrypted packet for O2O encryption: %v", err)
	}
	transpMsg := transport.Message{Payload: data, Type: encryptedMsg.Name()}
	return &transpMsg, nil
}

func (n *node) GenerateDHCurve() {
	n.crypto.DHCurve.Set(ecdh.X25519())
}

func (n *node) GetDHCurve() ecdh.Curve {
	return n.crypto.DHCurve.Get()
}

func (n *node) GenerateDHKey() (*ecdh.PrivateKey, error) {
	DHPrivateKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	return DHPrivateKey, err
}

func (n *node) GetDHPK() *ecdh.PublicKey {
	return n.crypto.DHPublicKey.Get()
}

func (n *node) ECDH(remotePK *ecdh.PublicKey) ([]byte, error) {
	productPK, err := n.crypto.DHPrivateKey.ECDH(remotePK)
	return productPK, err
}

func (n *node) GetDHSharedSecret() *ecdh.PublicKey {
	return n.crypto.DHSharedSecret.Get()
}

func (n *node) SetDHSharedSecret(secret *ecdh.PublicKey) {
	n.crypto.DHSharedSecret.Set(secret)
}

func (n *node) DHSharedSecretEqual(key *ecdh.PublicKey) bool {
	return n.crypto.DHSharedSecret.Equal(key)
}

func (n *node) EncryptDH(msg []byte) ([]byte, error) {
	//Encrypt a msg with the DH shared secret
	c := &n.crypto
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

func (n *node) DecryptDH(msg []byte) ([]byte, error) {
	//Decrypt a msg with the DH shared secret
	c := &n.crypto
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

func (n *node) EncryptDHMsg(msg *transport.Message) (*transport.Message, error) {
	c := &n.crypto
	marshaledPayload, err := msg.Payload.MarshalJSON()
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling packet in DH pkt encryption: %v", err)
	}

	pkA, err := x509.MarshalPKIXPublicKey(&c.KeyPair.PublicKey)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling local PK in DH pkt encryption: %v", err)
	}

	encryptedPayload, err := n.EncryptDH(marshaledPayload)
	if err != nil {
		return nil, xerrors.Errorf("error when encrypting packet in DH pkt encryption: %v", err)
	}

	sig, err := n.Sign(nil, []byte(msg.Type), encryptedPayload)
	if err != nil {
		return nil, xerrors.Errorf("error when signing packet in DH pkt encryption: %v", err)
	}

	encryptedMsg := types.DHEncryptedPkt{Payload: encryptedPayload, Type: msg.Type, RemoteKey: pkA, Signature: sig}
	data, err := json.Marshal(&encryptedMsg)
	if err != nil {
		return nil, xerrors.Errorf("error when marshaling msg in DH pkt encryption: %v", err)
	}

	transpMsg := transport.Message{Payload: data, Type: encryptedMsg.Name()}
	return &transpMsg, nil
}

func ConstructKeyToSend(n *node, dest string) (*ecdh.PublicKey, error) {
	//Build the partial shaerd secret to send to dest
	//That is g^(product of all 1to1 (init) shared secret except dest's)
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

func DHRound2(n *node, receivers map[string]struct{}) error {
	//Round 2 of the DH key exchange (send to all members the partial shared secret)
	//And wait for them to answer / timeout
	var waitGrp sync.WaitGroup
	var lock sync.Mutex
	removedPeers := make([]string, 0)
	round2Messages, err := BuildPartialSecrets(n, receivers)
	if err != nil {
		return err
	}
	for s := range receivers {
		//Create a waiting goroutine for all members
		//It either times out after 5s if the peer doesn't attest having received the key
		//Or receives an "ACK" and stop waiting
		if s == n.GetAddress() {
			continue
		}
		n.crypto.DHchannels.Add(s)
		waitGrp.Add(1)
		go func(c chan struct{}, peer string, msg transport.Message) {
			defer waitGrp.Done()
			for try := 0; try <= 2; try++ {
				//We resend the message every 2 seconds in case it got lost
				select {
				case <-c:
					return
				case <-time.After(time.Second * 2):
					erro := n.Unicast(peer, msg)
					if err != nil {
						n.logger.Err(erro).Msg("error when retrying DH round 2 msg to " + peer)
					}
				}
			}
			//assume the remote node is malicious or dead
			lock.Lock()
			removedPeers = append(removedPeers, peer)
			delete(receivers, peer)
			n.crypto.DHchannels.Delete(peer)
			delete(n.crypto.DHInitSecrets, peer)
			delete(n.crypto.DHPartialSecrets, peer)
			lock.Unlock()

			// Its dead. Remove it from the list of members
			n.peerCord.members.delete(peer)
		}(n.crypto.DHchannels.Get(s), s, round2Messages[s])
	}
	waitGrp.Wait()
	//After waiting for all goroutines to either timeout or receive ACK,
	//We remove peers who didn't answer
	for _, removedPeer := range removedPeers {
		erro := n.GroupCallRemove(removedPeer)
		if erro != nil {
			return xerrors.Errorf("error when removing unanswering peer: %v", err)
		}
	}

	return err
}

func BuildPartialSecrets(n *node, receivers map[string]struct{}) (map[string]transport.Message, error) {
	// Auxiliary function for StartDHKeyExchange sending the partial secrets to all other call members
	partialSecretsMessages := make(map[string]transport.Message)
	first := true
	callMembers := n.CreateCallMembers()
	for dest := range receivers {
		//For each member, we build the partial shared secret
		keyToSend, err := ConstructKeyToSend(n, dest)
		if err != nil {
			return nil, err
		}
		if first {
			//Then we have set the local knowledge of the shared secret
			first = false
			sharedSecretBytes, err := n.crypto.DHInitSecrets[dest].ECDH(keyToSend)
			if err != nil {
				return nil, xerrors.Errorf("error when generating shared secret bytes: %v", err)
			}
			secret, err := n.crypto.DHCurve.NewPublicKey(sharedSecretBytes)
			if err != nil {
				return nil, xerrors.Errorf("error when generating shared secret: %v", err)
			}
			n.crypto.DHSharedSecret.Set(secret)
		}
		//We store the partial secrets to make member addition lighter
		n.crypto.DHPartialSecrets[dest] = keyToSend
		//We build the message then send it
		localKey, err := x509.MarshalPKIXPublicKey(keyToSend)
		if err != nil {
			return nil, xerrors.Errorf("error in DH key exchange when marshaling partial shared secret for %v: %v", dest, err)
		}
		ssMsg := types.GroupCallDHSharedSecret{RemoteKey: localKey, MembersList: callMembers}
		data, err := json.Marshal(&ssMsg)

		if err != nil {
			return nil, xerrors.Errorf("error when marshaling DH init msg: %v", err)
		}

		ssTransportMsg := transport.Message{
			Type:    ssMsg.Name(),
			Payload: data,
		}
		partialSecretsMessages[dest] = ssTransportMsg
	}

	return partialSecretsMessages, nil
}

func (n *node) StartDHKeyExchange(receivers map[string]struct{}) error {
	//Start a DH key exchange with the receivers
	//We (re)set the DH related variables
	n.crypto.DHIsLeader.Set(true)
	n.crypto.DHInitSecrets = make(map[string](*ecdh.PrivateKey))
	n.crypto.DHchannels = StrChanMap{Map: make(map[string]chan struct{})}
	n.crypto.DHPartialSecrets = make(map[string]*ecdh.PublicKey)
	n.GenerateDHCurve()
	DHPrivateKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when starting DH key exchange: %v", err)
	}
	n.crypto.DHPrivateKey.Set(DHPrivateKey)
	n.crypto.DHPublicKey.Set(DHPrivateKey.PublicKey())
	multicastReceivers := make(map[string]struct{})
	for s := range receivers {
		//We keep all receivers that are correctly formated
		if IsAddress(s) {
			multicastReceivers[s] = struct{}{}
		}
	}
	receivers = multicastReceivers

	//ROUND 1: perform a DH key exchange with all receivers (init phase)
	localPKBytes, err := n.crypto.DHPublicKey.Marshal()
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
	var lock sync.Mutex

	multicastReceivers = make(map[string]struct{})
	for r := range receivers {
		multicastReceivers[r] = struct{}{}
	}

	for s := range multicastReceivers {
		//Start a goroutine for all receivers which will wait
		//for the remote DH public key to generate the 1to1 DH shared secrets
		n.crypto.DHchannels.Add(s)
		wg.Add(1)
		go func(c chan struct{}, peer string) {
			defer wg.Done()
			for try := 0; try <= 2; try++ {
				//We resend the message every 2 seconds in case it got lost
				select {
				case <-c:
					return
				case <-time.After(time.Second * 2):
					err := n.Unicast(peer, initTransportMsg)
					if err != nil {
						n.logger.Err(err).Msg("error retrying a DH init message to " + peer)
					}
				}
			}
			//assume the remote node is malicious or dead
			lock.Lock()
			delete(receivers, peer)
			n.crypto.DHchannels.Delete(peer)
			delete(n.crypto.DHInitSecrets, peer)
			delete(n.crypto.DHPartialSecrets, peer)
			lock.Unlock()

			// Its dead. Remove it from the list of members
			n.peerCord.members.delete(peer)
		}(n.crypto.DHchannels.Get(s), s)
	}

	err = n.NaiveMulticast(initTransportMsg, multicastReceivers)
	if err != nil {
		return xerrors.Errorf("error in DH key exchange init multicast: %v", err)
	}

	wg.Wait()

	return DHRound2(n, receivers)
}

func DHRemoveRound2(n *node, member string) error {
	//Round 2 of the Removal of a member in the DH group
	var waitGrp sync.WaitGroup
	var lock sync.Mutex
	removedPeers := make([]string, 0)

	round2Messages, err := BuildPartialSecretsRemove(n, member)
	for s := range n.crypto.DHInitSecrets {
		//We start waiting goroutines for all receivers
		if s == n.GetAddress() {
			continue
		}
		n.crypto.DHchannels.Add(s)
		waitGrp.Add(1)
		go func(c chan struct{}, peer string, msg transport.Message) {
			defer waitGrp.Done()
			for try := 0; try <= 2; try++ {
				//We resend the message every 2 seconds in case it got lost
				select {
				case <-c:
					return
				case <-time.After(time.Second * 2):
					erro := n.Unicast(peer, msg)
					if err != nil {
						n.logger.Err(erro).Msg("error when retrying DH round 2 msg to " + peer)
					}
				}
			}
			//assume the remote node is malicious or dead
			lock.Lock()
			removedPeers = append(removedPeers, peer)
			n.crypto.DHchannels.Delete(peer)
			delete(n.crypto.DHInitSecrets, peer)
			delete(n.crypto.DHPartialSecrets, peer)
			lock.Unlock()

			// Its dead. Remove it from the list of members
			n.peerCord.members.delete(peer)
		}(n.crypto.DHchannels.Get(s), s, round2Messages[s])
	}
	waitGrp.Wait()

	for _, removedPeer := range removedPeers {
		//We remove the peers who didn't attest building the shared secret
		erro := n.GroupCallRemove(removedPeer)
		if erro != nil {
			return xerrors.Errorf("error when removing unanswering peer: %v", err)
		}
	}

	return err
}

func BuildPartialSecretsRemove(n *node, member string) (map[string]transport.Message, error) {
	//Send partial secrets to all receivers after removing member
	newSharedSecretSet := false
	round2Messages := make(map[string]transport.Message)
	callMembers := n.CreateCallMembers()
	for dest := range n.crypto.DHPartialSecrets {
		//We build the partial shared secrets for all receivers
		if dest == n.GetAddress() {
			continue
		}
		//Build the key
		keyToSend, err := BuildPartialSecretsRemoveBuildKeyToSend(n, dest)
		if err != nil {
			return nil, err
		}
		//Update the knowledge of partial secrets for lighter member addition
		n.crypto.DHPartialSecrets[dest] = keyToSend
		//Build the message then send it
		localKey, err := x509.MarshalPKIXPublicKey(keyToSend)
		if err != nil {
			return nil, xerrors.Errorf("error in DH key exchange when marshaling partial shared secret for %v: %v", dest, err)
		}
		ssMsg := types.GroupCallDHSharedSecret{RemoteKey: localKey, MembersList: callMembers}
		data, err := json.Marshal(&ssMsg)

		if err != nil {
			return nil, xerrors.Errorf("error when marshaling DH init msg: %v", err)
		}

		ssTransportMsg := transport.Message{
			Type:    ssMsg.Name(),
			Payload: data,
		}

		round2Messages[dest] = ssTransportMsg

		//If it's the first time we build a partial secret, we compute the complete shared secret and store it
		if !newSharedSecretSet {
			newSS, err := n.crypto.DHInitSecrets[dest].ECDH(keyToSend)
			if err != nil {
				return nil, xerrors.Errorf("error when computing new DH SS bytes for removal of %v: %v", member, err)
			}
			secret, err := n.crypto.DHCurve.NewPublicKey(newSS)
			if err != nil {
				return nil, xerrors.Errorf("error when computing new DH SS for removal of %v: %v", member, err)
			}
			n.crypto.DHSharedSecret.Set(secret)
			newSharedSecretSet = true
		}
	}

	return round2Messages, nil
}

func BuildPartialSecretsRemoveBuildKeyToSend(n *node, dest string) (*ecdh.PublicKey, error) {
	//Auxiliary function building the partial secret for dest adding an iffset (random key)
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

func (n *node) GroupCallRemove(member string) error {
	//Remove member from the DH group (=call group)
	if !IsAddress(member) {
		return xerrors.Errorf("error in GoupCallRemove: member isn't an IP address with port")
	}
	if !n.crypto.DHIsLeader.Get() {
		return nil
	}
	//If member = leader: the call must end
	if member == n.conf.Socket.GetAddress() {
		return nil
	}
	//Generate a new random key (offset to provide forward secrecy)
	newKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when generating new key to remove member %v: %v", member, err)
	}
	//Add the offset to the current offset (if any)
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

	//Remove the member from the DH group: forget about its init key and partial secret
	delete(n.crypto.DHInitSecrets, member)
	delete(n.crypto.DHPartialSecrets, member)
	return DHRemoveRound2(n, member)
}

func DHAddRound2(n *node, member string, newKey *ecdh.PrivateKey, secret *ecdh.PublicKey) error {
	//Member addition round 2
	round2Messages, err := BuildPartialSecretsInAddition(n, member, newKey)
	var waitGrp sync.WaitGroup
	var lock sync.Mutex
	removedPeers := make([]string, 0)
	for s := range n.crypto.DHPartialSecrets {
		//Start waiting goroutines for each receiver
		if s == n.GetAddress() {
			continue
		}
		n.crypto.DHchannels.Add(s)
		waitGrp.Add(1)
		go func(c chan struct{}, peer string, msg transport.Message) {
			defer waitGrp.Done()
			for try := 0; try <= 2; try++ {
				//We resend the message every 2 seconds in case it got lost
				select {
				case <-c:
					return
				case <-time.After(time.Second * 2):
					erro := n.Unicast(peer, msg)
					if erro != nil {
						n.logger.Err(erro).Msg("error when retrying round 2 msg to " + peer + " when adding " + member)
					}
				}
			}
			//assume the remote node is malicious or dead
			lock.Lock()
			removedPeers = append(removedPeers, peer)
			n.crypto.DHchannels.Delete(peer)
			delete(n.crypto.DHInitSecrets, peer)
			delete(n.crypto.DHPartialSecrets, peer)
			lock.Unlock()

			// Its dead. Remove it from the list of members
			n.peerCord.members.delete(peer)
		}(n.crypto.DHchannels.Get(s), s, round2Messages[s])
	}

	waitGrp.Wait()

	for _, removedPeer := range removedPeers {
		//Remove receivers who didn't send back an "ACK"
		erro := n.GroupCallRemove(removedPeer)
		if erro != nil {
			return xerrors.Errorf("error when removing unanswering peer: %v", err)
		}
	}
	n.crypto.DHPartialSecrets[member] = secret
	return err
}

func BuildPartialSecretsInAddition(n *node, member string, newKey *ecdh.PrivateKey) (map[string]transport.Message, error) {
	round2Messages := make(map[string]transport.Message)
	//We compute and store the new shared secret
	newMemberSecret, ok := n.crypto.DHInitSecrets[member]
	if !ok {
		return nil, xerrors.Errorf("error when retrieving new member (%v)'s shared secret", member)
	}
	newSharedSecretBytes, err := n.crypto.DHSharedSecret.ECDH(newMemberSecret)
	if err != nil {
		return nil, xerrors.Errorf("error when generating new shared PK bytes to add member %v: %v", member, err)
	}
	secret, err := n.crypto.DHCurve.NewPublicKey(newSharedSecretBytes)
	if err != nil {
		return nil, xerrors.Errorf("error when generating new shared PK to add member %v: %v", member, err)
	}
	n.crypto.DHSharedSecret.Set(secret)

	callMembers := n.CreateCallMembers()
	callMembers[member] = struct{}{}
	for s, key := range n.crypto.DHPartialSecrets {
		//For all member we update the shared secret and send it
		if s == n.GetAddress() {
			continue
		}
		//Compute the new partial secret
		newPartialSecretKeyBytes, err := newKey.ECDH(key)
		if err != nil {
			return nil, xerrors.Errorf("error when generating new patial secret bytes for %v to add member %v: %v", s, member, err)
		}
		newPartialSecretKey, err := n.crypto.DHCurve.NewPublicKey(newPartialSecretKeyBytes)
		if err != nil {
			return nil, xerrors.Errorf("error when generating new partial secret for %v to add member %v: %v", s, member, err)
		}
		newPartialSecretKeyBytes, err = newMemberSecret.ECDH(newPartialSecretKey)
		if err != nil {
			return nil, xerrors.Errorf("error when generating new patial secret bytes for %v to add member %v: %v", s, member, err)
		}
		newPartialSecretKey, err = n.crypto.DHCurve.NewPublicKey(newPartialSecretKeyBytes)
		if err != nil {
			return nil, xerrors.Errorf("error when generating new partial secret for %v to add member %v: %v", s, member, err)
		}
		//Update the partial secret
		n.crypto.DHPartialSecrets[s] = newPartialSecretKey
		newPartialSecretKeyMarshaled, err := x509.MarshalPKIXPublicKey(newPartialSecretKey)
		if err != nil {
			return nil, xerrors.Errorf("error when marshaling partial key for %v to add %v: %v", s, member, err)
		}
		//Create and send a message with the partial secret
		msg := types.GroupCallDHSharedSecret{RemoteKey: newPartialSecretKeyMarshaled, MembersList: callMembers}
		data, err := json.Marshal(&msg)
		if err != nil {
			return nil, xerrors.Errorf("error when marshaling DH addition msg of %v for %v: %v", member, s, err)
		}

		transportMsg := transport.Message{
			Type:    msg.Name(),
			Payload: data,
		}
		round2Messages[s] = transportMsg
	}

	return round2Messages, nil
}

func (n *node) GroupCallAdd(member string) error {
	//Add member to the DH group
	if !IsAddress(member) {
		return xerrors.Errorf("error in GoupCallAdd: member isn't an IP address with port")
	}
	if !n.crypto.DHIsLeader.Get() {
		return nil
	}

	//First, do a DH key exchange with the new member
	localPKBytes, err := n.crypto.DHPublicKey.Marshal()
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
	n.crypto.DHchannels.Add(member)
	wg.Add(1)
	//Goroutine waiting for the new member to send its part of the DH key
	go func(c chan struct{}, peer string) {
		defer wg.Done()
		for try := 0; try <= 2; try++ {
			//We resend the message every 2 seconds in case it got lost
			select {
			case <-c:
				return
			case <-time.After(time.Second * 2):
				err := n.Unicast(peer, initTransportMsg)
				if err != nil {
					n.logger.Err(err).Msg("error retrying to send DH init message to new member " + peer)
				}
			}
		}
		n.crypto.DHchannels.Delete(peer)
		delete(n.crypto.DHPartialSecrets, peer)
		delete(n.crypto.DHInitSecrets, peer)
	}(n.crypto.DHchannels.Get(member), member)

	err = n.Unicast(member, initTransportMsg)
	if err != nil {
		return xerrors.Errorf("error when unicasting individual DH to additional member %v: %v", member, err)
	}

	wg.Wait()

	//Generate the random key (offset)
	newKey, err := n.crypto.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error when generating new key to add member %v: %v", member, err)
	}
	//Add it to the existing offset (if any)
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

	//Add the offset to the shared secret
	newSSKey, err := n.crypto.DHSharedSecret.ECDH(newKey)
	if err != nil {
		return xerrors.Errorf("error when generating new SS bytes to add member %v: %v", member, err)
	}
	secret, err := n.crypto.DHCurve.NewPublicKey(newSSKey)
	if err != nil {
		return xerrors.Errorf("error when generating new SS to add member %v: %v", member, err)
	}
	n.crypto.DHSharedSecret.Set(secret)

	newPartialSecretKeyMarshaled, err := n.crypto.DHSharedSecret.Marshal()
	if err != nil {
		return xerrors.Errorf("error when marshaling partial key for %v to add %v: %v", member, member, err)
	}

	callMembers := n.CreateCallMembers()
	callMembers[member] = struct{}{}
	//Send to the new member its partial secret
	msg := types.GroupCallDHSharedSecret{RemoteKey: newPartialSecretKeyMarshaled, MembersList: callMembers}
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

	return DHAddRound2(n, member, newKey, secret)
}

func (n *node) GroupCallEnd() {
	//Resets the DH related variables
	n.crypto.DHCurve.Set(nil)
	n.crypto.DHSharedPersonalSecret.Set(nil)
	n.crypto.DHSharedSecret.Set(nil)
	n.crypto.DHPrivateKey.Set(nil)
	n.crypto.DHPublicKey.Set(nil)
	n.crypto.DHIsLeader.Set(false)
	n.crypto.DHchannels.Mutex.Lock()
	for s, ch := range n.crypto.DHchannels.Map {
		close(ch)
		delete(n.crypto.DHchannels.Map, s)
	}
	n.crypto.DHchannels.Mutex.Unlock()
	for s := range n.crypto.DHInitSecrets {
		delete(n.crypto.DHInitSecrets, s)
	}
	for s := range n.crypto.DHPartialSecrets {
		delete(n.crypto.DHPartialSecrets, s)
	}
}

func (n *node) ExecGroupCallDHIndividual(msg types.Message, packet transport.Packet) error {
	//Message handler for DH Round 1
	message, ok := msg.(*types.GroupCallDHIndividual)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}
	//Retrieve the DH public key from the message
	remoteK, err := x509.ParsePKIXPublicKey(message.RemoteKey)
	if err != nil {
		return xerrors.Errorf("error when parsing remote DH individual PK: %v", err)
	}
	remoteKey, ok := remoteK.(*ecdh.PublicKey)
	if !ok {
		return xerrors.Errorf("error when casting remote DH individual PK: type %T", remoteK)
	}
	if n.crypto.DHIsLeader.Get() {
		//If n is the leader then it stores the 1to1 shared secret as a DH private key
		sharedSecretBytes, err := n.crypto.DHPrivateKey.ECDH(remoteKey)
		if err != nil {
			return xerrors.Errorf("error in individual DH key exchange when generating secret bytes: %v", err)
		}
		sharedSecret, err := n.crypto.DHCurve.NewPrivateKey(sharedSecretBytes)
		if err != nil {
			return xerrors.Errorf("error in individual DH key exchange when generating secret: %v", err)
		}
		n.crypto.DHInitSecrets[packet.Header.Source] = sharedSecret
		returnChan, ok := n.crypto.DHchannels.SafeGet(packet.Header.Source)
		if ok {
			returnChan <- struct{}{}
			n.crypto.DHchannels.Delete(packet.Header.Source)
		}
		return nil
	}
	//If it's not the leader then it generates its DH key and sends the public part to the leader
	n.crypto.DHCurve.Set(remoteKey.Curve())
	privateK, err := remoteKey.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating key: %v", err)
	}
	n.crypto.DHPrivateKey.Set(privateK)
	n.crypto.DHPublicKey.Set(privateK.PublicKey())
	sharedSecret, err := n.crypto.DHPrivateKey.ECDH(remoteKey)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating secret bytes: %v", err)
	}
	sharedPersonalSecret, err := n.crypto.DHCurve.NewPublicKey(sharedSecret)
	if err != nil {
		return xerrors.Errorf("error in individual DH key exchange when generating secret: %v", err)
	}
	n.crypto.DHSharedPersonalSecret.Set(sharedPersonalSecret)

	//Build the answer message then send it
	localPublicKeyBytes, err := n.crypto.DHPublicKey.Marshal()
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
	//Message handler for DH round 2
	message, ok := msg.(*types.GroupCallDHSharedSecret)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	if n.crypto.DHIsLeader.Get() {
		//If n is leader then it's just an ACK
		returnChan, ok := n.crypto.DHchannels.SafeGet(packet.Header.Source)
		if ok {
			returnChan <- struct{}{}
			n.crypto.DHchannels.Delete(packet.Header.Source)
		}
		return nil
	}
	//Otherwise, n retrieves the partial secret from the message
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
	//Then it computes the shared secret
	finalSecretBytes, err := sharedSecretSK.ECDH(remoteKey)
	if err != nil {
		return xerrors.Errorf("error when generating final shared secret: %v", err)
	}
	sharedSecret, err := n.crypto.DHCurve.NewPublicKey(finalSecretBytes)
	if err != nil {
		return xerrors.Errorf("error when creating shared secret: %v", err)
	}
	n.crypto.DHSharedSecret.Set(sharedSecret)

	//And finally sends back an ACK (empty message)
	ackMsg := types.GroupCallDHSharedSecret{}
	data, err := json.Marshal(&ackMsg)
	if err != nil {
		return xerrors.Errorf("error in DH Shared secret ACK marshaling: %v", err)
	}
	trspMsg := transport.Message{Payload: data, Type: ackMsg.Name()}
	err = n.Unicast(packet.Header.Source, trspMsg)
	if err != nil {
		return xerrors.Errorf("error when unicasting SS ACK: %v", err)
	}

	delete(message.MembersList, n.GetAddress())
	n.peerCord.members.mutex.Lock()
	n.peerCord.members.data = message.MembersList
	n.peerCord.members.mutex.Unlock()

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
	//Message handler for messages encrypted with One to One encryption
	message, ok := msg.(*types.O2OEncryptedPkt)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	//We verify the public ID if known or store it if new
	idKnown, ok := n.VerifyPID(packet.Header.Source, message.RemoteID, message.RemoteKey)
	if !ok {
		n.AddPublicKey(packet.Header.Source, message.RemoteID, message.RemoteKey)
	} else if !idKnown {
		//We neglect the msg because it's assumed to be forged by a malicious node
		if n.guiReady() {
			storedID, _ := n.GetPeerKey(packet.Header.Source)
			choice := n.gui.PromptBinaryChoice(packet.Header.Source+" = "+storedID.Str, packet.Header.Source+" = "+message.RemoteID)
			if !choice {
				n.AddPublicKey(packet.Header.Source, message.RemoteID, message.RemoteKey)
			}
		}
		//If there is no GUI, we keep the first (should only happen in tests thus we don't care)
	}

	//We verify the message's signature
	hash := sha256.New()
	_, err := hash.Write(message.Key)
	if err != nil {
		return xerrors.Errorf("error when hashing msg: %v", err)
	}
	_, err = hash.Write([]byte(message.Type))
	if err != nil {
		return xerrors.Errorf("error when hashing msg: %v", err)
	}
	_, err = hash.Write(message.Payload)
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

	//We decrypt the random key used to encrypt the message using our RSA private key
	dectyptedKey, err := n.DecryptOneToOne(message.Key)
	if err != nil {
		return xerrors.Errorf("error decrypting O2O encrypted pkt: %v", err)
	}

	//Then we decrypt the message with the random key
	ciph, err := aes.NewCipher(dectyptedKey)
	if err != nil {
		return xerrors.Errorf("error decrypting msg for O2O encryption: %v", err)
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return xerrors.Errorf("error decrypting msg for O2O encryption: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(message.Payload) < nonceSize {
		return xerrors.Errorf("error decrypting msg for O2O encryption: msg size is smaller than nonce")
	}

	nonce, ciphertext := message.Payload[:nonceSize], message.Payload[nonceSize:]
	decryptedMsg, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return xerrors.Errorf("error decrypting msg for O2O encryption: %v", err)
	}

	//Now that it's decrypted, we can retrieve the packet and process it
	var payload json.RawMessage
	err = payload.UnmarshalJSON(decryptedMsg)
	if err != nil {
		return xerrors.Errorf("error when unmarshaling decrypted O2O message: %v", err)
	}

	header := packet.Header.Copy()
	pkt := transport.Packet{Header: &header, Msg: &transport.Message{Payload: payload, Type: message.Type}}

	return n.cryptoProcessDirect(pkt)
}

func (n *node) ExecDHEncryptedPkt(msg types.Message, packet transport.Packet) error {
	//Message handler for DH encrypted messages
	message, ok := msg.(*types.DHEncryptedPkt)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	//We just have to decrypt the packet then process it
	decryptedPayload, err := n.DecryptDH(message.Payload)
	if err != nil {
		return xerrors.Errorf("error decrypting DH encrypted pkt: %v", err)
	}
	decryptedMsg := transport.Message{Type: message.Type, Payload: decryptedPayload}
	header := packet.Header.Copy()
	pkt := transport.Packet{Header: &header, Msg: &decryptedMsg}

	// Process the message directly
	return n.cryptoProcessDirect(pkt)
}

func (n *node) cryptoProcessDirect(pkt transport.Packet) error {
	msgType := pkt.Msg.Type
	n.logger.Warn().Msgf("Received encrypted msg of type %v", msgType)

	err := n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		n.logger.Warn().Err(err).Msg("failed to process packet")
	}

	return err
}
