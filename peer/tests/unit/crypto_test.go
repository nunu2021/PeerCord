package unit

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
	"go.dedis.ch/cs438/types"
)

func randInt(N int) int {
	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(N)))
	return int(randNum.Int64())
}

func TestCrypto_DH_Enc_Dec(t *testing.T) {
	//Create nodes A and B
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	//Create a random message
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	//Generate a fake DH key for A anb B
	nodeA.GenerateDHCurve()
	privateKey, err := nodeA.GenerateDHKey()
	require.NoError(t, err)
	nodeB.SetDHSharedSecret(privateKey.PublicKey())
	nodeA.SetDHSharedSecret(privateKey.PublicKey())
	//Encrypt at A
	encryptedMsg, err := nodeA.EncryptDH(randomBytes)
	require.NoError(t, err)
	//Decrypt at B
	decryptedMsg, err := nodeB.DecryptDH(encryptedMsg)
	require.NoError(t, err)
	require.Equal(t, true, bytes.Equal(decryptedMsg, randomBytes))
}

func TestCrypto_DH_Enc_Dec_Wrong_Key(t *testing.T) {
	//Simple test verifying that the DH enc/dec works
	//Create nodes
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	//Create a random message
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	//Create 2 fake DH keys, one for A, one for B
	nodeA.GenerateDHCurve()
	privateKey, err := nodeA.GenerateDHKey()
	require.NoError(t, err)
	nodeB.GenerateDHCurve()
	nodeA.SetDHSharedSecret(privateKey.PublicKey())
	privateKey, err = nodeA.GenerateDHKey()
	require.NoError(t, err)
	nodeB.SetDHSharedSecret(privateKey.PublicKey())
	//Encrypt the message at A
	encryptedMsg, err := nodeA.EncryptDH(randomBytes)
	require.NoError(t, err)
	//Decrypt it at B
	_, err = nodeB.DecryptDH(encryptedMsg)
	require.Error(t, err)
}

func TestCrypto_OtO_Enc_Dec(t *testing.T) {
	//Create nodes A and B
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	//Generate a random message
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	//Generate a key pair
	err := nodeA.GenerateKeyPair()
	require.NoError(t, err)
	pubKey := nodeA.GetPK()
	keyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	require.NoError(t, err)
	nodeB.AddPublicKey("127.0.0.1:0", "+33600000000", keyBytes)
	//Encrypt the message at B
	encryptedMsg, err := nodeB.EncryptOneToOne(randomBytes, "127.0.0.1:0")
	require.NoError(t, err)
	//Decrypt it ad A
	decryptedMsg, err := nodeA.DecryptOneToOne(encryptedMsg)
	require.NoError(t, err)
	require.Equal(t, true, bytes.Equal(decryptedMsg, randomBytes))
}

func TestCrypto_OtO_Enc_Dec_Wrong_Key(t *testing.T) {
	//Create nodes A and B
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	//Create a random message
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)

	//Create 2 fake key pairs
	err := nodeA.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, nodeB.GenerateKeyPair())
	pubKey := nodeB.GetPK()
	keyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	require.NoError(t, err)
	nodeB.AddPublicKey("127.0.0.1:0", "+33600000000", keyBytes)
	//Encrypt with one
	encryptedMsg, err := nodeB.EncryptOneToOne(randomBytes, "127.0.0.1:0")
	require.NoError(t, err)
	//Decrypt with the other
	_, err = nodeA.DecryptOneToOne(encryptedMsg)
	require.Error(t, err)
}

func TestCrypto_Send_Recv_OtO_Enc_Msg(t *testing.T) {
	//Generate 2 nodes
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeA.AddPeer(nodeB.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())

	nodeA.Start()
	nodeB.Start()

	//Generate 2 key paris
	nodeA.GenerateKeyPair()
	nodeA.SetPublicID("+33600000000")
	nodeB.GenerateKeyPair()
	nodeB.SetPublicID("+33600000001")

	//Generate a random chat message
	size := randInt(500)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	chatMsg := types.ChatMessage{Message: hex.EncodeToString(randomBytes)}
	data, err := json.Marshal(&chatMsg)
	require.NoError(t, err)
	nodeB.GenerateKeyPair()
	transpMsg := transport.Message{Payload: data, Type: chatMsg.Name()}

	//Store knowledge of each other's public ID
	nodeAPK := nodeA.GetPK()
	keyBytes, err := x509.MarshalPKIXPublicKey(&nodeAPK)
	require.NoError(t, err)
	nodeB.AddPublicKey(nodeA.GetAddr(), "+33600000000", keyBytes)

	nodeBPK := nodeB.GetPK()
	keyBytes, err = x509.MarshalPKIXPublicKey(&nodeBPK)
	require.NoError(t, err)
	nodeA.AddPublicKey(nodeB.GetAddr(), "+33600000001", keyBytes)

	//Encrypt the message at A
	msg, err := nodeA.EncryptOneToOneMsg(&transpMsg, nodeB.GetAddr())
	require.NoError(t, err)

	//Send it to B
	require.NoError(t, nodeA.Unicast(nodeB.GetAddr(), *msg))
	time.Sleep(time.Second * 2)
	//B should get the chat message
	require.Equal(t, 1, len(nodeB.GetChatMsgs()))
	require.Equal(t, nodeB.GetChatMsgs()[0].Message, chatMsg.Message)
}

func TestCrypto_Send_Recv_DH_Enc_Msg(t *testing.T) {
	//Generate nodes A,B,C
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeC.Stop()

	nodeA.AddPeer(nodeB.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())
	nodeA.AddPeer(nodeC.GetAddr())
	nodeB.AddPeer(nodeC.GetAddr())
	nodeC.AddPeer(nodeB.GetAddr())
	nodeC.AddPeer(nodeA.GetAddr())

	nodeA.Start()
	nodeB.Start()
	nodeC.Start()

	nodeA.GenerateKeyPair()
	nodeB.GenerateKeyPair()
	nodeC.GenerateKeyPair()

	//Do a DH key exchange with all 3
	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	require.NoError(t, nodeA.StartDHKeyExchange(receivers))
	time.Sleep(time.Second)

	//Generate a random message
	size := randInt(500)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	chatMsg := types.ChatMessage{Message: hex.EncodeToString(randomBytes)}
	data, err := json.Marshal(&chatMsg)
	require.NoError(t, err)
	trpMsg := transport.Message{Payload: data, Type: chatMsg.Name()}

	//Encrypt at A
	transpMsg, err := nodeA.EncryptDHMsg(&trpMsg)
	require.NoError(t, err)

	//Make A cast to B and C
	receiversMap := make(map[string]struct{})
	receiversMap[nodeB.GetAddr()] = struct{}{}
	receiversMap[nodeC.GetAddr()] = struct{}{}
	require.NoError(t, nodeA.NaiveMulticast(*transpMsg, receiversMap))
	time.Sleep(time.Second * 2)
	//B and C should have received the message
	require.Equal(t, 1, len(nodeB.GetChatMsgs()))
	require.Equal(t, chatMsg.Message, nodeB.GetChatMsgs()[0].Message)
	require.Equal(t, 1, len(nodeC.GetChatMsgs()))
	require.Equal(t, chatMsg.Message, nodeC.GetChatMsgs()[0].Message)
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
func TestCrypto_DH_Key_Exchange(t *testing.T) {
	//Generate nodes A,B,C,D
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeC.Stop()

	nodeD := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeD.Stop()
	nodeA.AddPeer(nodeB.GetAddr())
	nodeA.AddPeer(nodeC.GetAddr())
	nodeA.AddPeer(nodeD.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())
	nodeB.AddPeer(nodeC.GetAddr())
	nodeB.AddPeer(nodeD.GetAddr())
	nodeC.AddPeer(nodeA.GetAddr())
	nodeC.AddPeer(nodeB.GetAddr())
	nodeC.AddPeer(nodeD.GetAddr())
	nodeD.AddPeer(nodeA.GetAddr())
	nodeD.AddPeer(nodeB.GetAddr())
	nodeD.AddPeer(nodeC.GetAddr())
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()
	nodeD.Start()

	//Do a DH key exchange
	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	//Manually compute the shared secret
	curve := nodeA.GetDHCurve()
	ab, err := nodeA.ECDH(nodeB.GetDHPK())
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.ECDH(nodeC.GetDHPK())
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.ECDH(nodeD.GetDHPK())
	require.NoError(t, err)
	adSK, err := curve.NewPrivateKey(ad)
	require.NoError(t, err)
	abac, err := abSK.ECDH(acSK.PublicKey())
	require.NoError(t, err)
	abacPK, err := curve.NewPublicKey(abac)
	require.NoError(t, err)
	abacad, err := adSK.ECDH(abacPK)
	require.NoError(t, err)
	abacadPK, err := curve.NewPublicKey(abacad)
	require.NoError(t, err)

	//They should all have the sharead secret
	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeB.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeC.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeD.DHSharedSecretEqual(abacadPK))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// B is late
func TestCrypto_DH_Key_Exchange_Late_Answering(t *testing.T) {
	//Generate nodes A,B,C,D
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeC.Stop()

	nodeD := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeD.Stop()
	nodeA.AddPeer(nodeB.GetAddr())
	nodeA.AddPeer(nodeC.GetAddr())
	nodeA.AddPeer(nodeD.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())
	nodeB.AddPeer(nodeC.GetAddr())
	nodeB.AddPeer(nodeD.GetAddr())
	nodeC.AddPeer(nodeA.GetAddr())
	nodeC.AddPeer(nodeB.GetAddr())
	nodeC.AddPeer(nodeD.GetAddr())
	nodeD.AddPeer(nodeA.GetAddr())
	nodeD.AddPeer(nodeB.GetAddr())
	nodeD.AddPeer(nodeC.GetAddr())
	nodeA.Start()
	nodeC.Start()
	nodeD.Start()

	//Do a DH key exchange
	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	go func() {
		time.Sleep(time.Second * 3)
		nodeB.Start()
	}()
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	//Manually compute the shared secret
	curve := nodeA.GetDHCurve()
	ab, err := nodeA.ECDH(nodeB.GetDHPK())
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.ECDH(nodeC.GetDHPK())
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.ECDH(nodeD.GetDHPK())
	require.NoError(t, err)
	adSK, err := curve.NewPrivateKey(ad)
	require.NoError(t, err)
	abac, err := abSK.ECDH(acSK.PublicKey())
	require.NoError(t, err)
	abacPK, err := curve.NewPublicKey(abac)
	require.NoError(t, err)
	abacad, err := adSK.ECDH(abacPK)
	require.NoError(t, err)
	abacadPK, err := curve.NewPublicKey(abacad)
	require.NoError(t, err)

	//They should all have the sharead secret
	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeB.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeC.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeD.DHSharedSecretEqual(abacadPK))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// B refuses to answer
func TestCrypto_DH_Key_Exchange_Ignoring_Peer(t *testing.T) {
	//Generate nodes A,B,C,D
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeC.Stop()

	nodeD := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeD.Stop()

	socketB, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)

	nodeA.AddPeer(socketB.GetAddress())
	nodeA.AddPeer(nodeC.GetAddr())
	nodeA.AddPeer(nodeD.GetAddr())
	nodeC.AddPeer(nodeA.GetAddr())
	nodeC.AddPeer(socketB.GetAddress())
	nodeC.AddPeer(nodeD.GetAddr())
	nodeD.AddPeer(nodeA.GetAddr())
	nodeD.AddPeer(socketB.GetAddress())
	nodeD.AddPeer(nodeC.GetAddr())
	nodeA.Start()
	nodeC.Start()
	nodeD.Start()

	//Do a DH key exchange with all
	receivers := make(map[string]struct{})
	receivers[socketB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	//Manually compute the shared secret as if only A,C,D where in the key exchange
	curve := nodeA.GetDHCurve()
	ac, err := nodeA.ECDH(nodeC.GetDHPK())
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.ECDH(nodeD.GetDHPK())
	require.NoError(t, err)
	adSK, err := curve.NewPrivateKey(ad)
	require.NoError(t, err)
	acad, err := acSK.ECDH(adSK.PublicKey())
	require.NoError(t, err)
	acadPK, err := curve.NewPublicKey(acad)
	require.NoError(t, err)

	//A,C,D should have the shared secret
	require.Equal(t, true, nodeA.DHSharedSecretEqual(acadPK))
	require.Equal(t, true, nodeC.DHSharedSecretEqual(acadPK))
	require.Equal(t, true, nodeD.DHSharedSecretEqual(acadPK))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C
// Then D joins
func TestCrypto_DH_Addition(t *testing.T) {
	//Generate nodes A,B,C,D
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeC.Stop()

	nodeD := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeD.Stop()

	nodeA.AddPeer(nodeB.GetAddr())
	nodeA.AddPeer(nodeC.GetAddr())
	nodeA.AddPeer(nodeD.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())
	nodeB.AddPeer(nodeC.GetAddr())
	nodeB.AddPeer(nodeD.GetAddr())
	nodeC.AddPeer(nodeA.GetAddr())
	nodeC.AddPeer(nodeB.GetAddr())
	nodeC.AddPeer(nodeD.GetAddr())
	nodeD.AddPeer(nodeA.GetAddr())
	nodeD.AddPeer(nodeB.GetAddr())
	nodeD.AddPeer(nodeC.GetAddr())
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()
	nodeD.Start()

	//Do a DH key exchange with A,B,C
	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	//Manually compute the shared secret
	curve := nodeA.GetDHCurve()
	ab, err := nodeA.ECDH(nodeB.GetDHPK())
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.ECDH(nodeC.GetDHPK())
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	abac, err := abSK.ECDH(acSK.PublicKey())
	require.NoError(t, err)
	abacPK, err := curve.NewPublicKey(abac)
	require.NoError(t, err)

	//After the key exchange A,B,C should have the shared secret
	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacPK))
	require.Equal(t, true, nodeB.DHSharedSecretEqual(abacPK))
	require.Equal(t, true, nodeC.DHSharedSecretEqual(abacPK))

	//Add D to the call
	err = nodeA.GroupCallAdd(nodeD.GetAddr())
	require.NoError(t, err)

	//They should all have the same secret (we can't compute it manually because of the random offset)
	require.NotEqual(t, nil, nodeD.GetDHSharedSecret())
	require.Equal(t, false, nodeD.DHSharedSecretEqual(abacPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// Then C leaves
func TestCrypto_DH_Removal(t *testing.T) {
	//Generate the nodes A,B,C,D
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeC.Stop()

	nodeD := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeD.Stop()

	nodeA.AddPeer(nodeB.GetAddr())
	nodeA.AddPeer(nodeC.GetAddr())
	nodeA.AddPeer(nodeD.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())
	nodeB.AddPeer(nodeC.GetAddr())
	nodeB.AddPeer(nodeD.GetAddr())
	nodeC.AddPeer(nodeA.GetAddr())
	nodeC.AddPeer(nodeB.GetAddr())
	nodeC.AddPeer(nodeD.GetAddr())
	nodeD.AddPeer(nodeA.GetAddr())
	nodeD.AddPeer(nodeB.GetAddr())
	nodeD.AddPeer(nodeC.GetAddr())
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()
	nodeD.Start()

	//Do a DH key exchange with all nodes
	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	//Manually compute the shared secret
	curve := nodeA.GetDHCurve()
	ab, err := nodeA.ECDH(nodeB.GetDHPK())
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.ECDH(nodeC.GetDHPK())
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.ECDH(nodeD.GetDHPK())
	require.NoError(t, err)
	adSK, err := curve.NewPrivateKey(ad)
	require.NoError(t, err)
	abac, err := abSK.ECDH(acSK.PublicKey())
	require.NoError(t, err)
	abacPK, err := curve.NewPublicKey(abac)
	require.NoError(t, err)
	abacad, err := adSK.ECDH(abacPK)
	require.NoError(t, err)
	abacadPK, err := curve.NewPublicKey(abacad)
	require.NoError(t, err)

	//They should all have the shared secret after the key exchange
	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))

	//We remove C from the call
	nodeA.GroupCallRemove(nodeC.GetAddr())

	//A, B and D should all have the same secret distinct from the initial one
	require.Equal(t, false, nodeA.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))
	require.NotEqual(t, nil, nodeA.GetDHSharedSecret())
}
