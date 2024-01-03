package unit

import (
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
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	nodeA.GenerateDHCurve()
	privateKey, err := nodeA.GenerateDHKey()
	require.NoError(t, err)
	nodeB.SetDHSharedSecret(privateKey.PublicKey())
	nodeA.SetDHSharedSecret(privateKey.PublicKey())
	encryptedMsg, err := nodeA.EncryptDH(randomBytes)
	require.NoError(t, err)
	decryptedMsg, err := nodeB.DecryptDH(encryptedMsg)
	require.NoError(t, err)
	require.Equal(t, string(decryptedMsg), string(randomBytes))
}

func TestCrypto_DH_Enc_Dec_Wrong_Key(t *testing.T) {
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	nodeA.GenerateDHCurve()
	privateKey, err := nodeA.GenerateDHKey()
	require.NoError(t, err)
	nodeB.GenerateDHCurve()
	nodeA.SetDHSharedSecret(privateKey.PublicKey())
	privateKey, err = nodeA.GenerateDHKey()
	require.NoError(t, err)
	nodeB.SetDHSharedSecret(privateKey.PublicKey())
	encryptedMsg, err := nodeA.EncryptDH(randomBytes)
	require.NoError(t, err)
	_, err = nodeB.DecryptDH(encryptedMsg)
	require.Error(t, err)
}

func TestCrypto_OtO_Enc_Dec(t *testing.T) {
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	size, _ = rand.Read(randomBytes)
	t.Logf("bytes size = %v", size)
	err := nodeA.GenerateKeyPair()
	require.NoError(t, err)
	pubKey := nodeA.GetPK()
	tim := time.Now()
	keyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	require.NoError(t, err)
	nodeB.AddPublicKey("127.0.0.1:0", "+33600000000", keyBytes)
	encryptedMsg, err := nodeB.EncryptOneToOne(randomBytes, "127.0.0.1:0")
	t.Logf("encryption time = %v", time.Since(tim))
	require.NoError(t, err)
	tim = time.Now()
	decryptedMsg, err := nodeA.DecryptOneToOne(encryptedMsg)
	t.Logf("decryption time = %v", time.Since(tim))
	require.NoError(t, err)
	require.Equal(t, string(decryptedMsg), string(randomBytes))
}

func TestCrypto_OtO_Enc_Dec_Wrong_Key(t *testing.T) {
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	size, _ = rand.Read(randomBytes)
	t.Logf("bytes size = %v", size)
	err := nodeA.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, nodeB.GenerateKeyPair())
	pubKey := nodeB.GetPK()
	keyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	require.NoError(t, err)
	nodeB.AddPublicKey("127.0.0.1:0", "+33600000000", keyBytes)
	encryptedMsg, err := nodeB.EncryptOneToOne(randomBytes, "127.0.0.1:0")
	require.NoError(t, err)
	_, err = nodeA.DecryptOneToOne(encryptedMsg)
	require.Error(t, err)
}

func TestCrypto_Send_Recv_OtO_Enc_Msg(t *testing.T) {
	transp := udp.NewUDP()

	nodeA := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeA.Stop()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(false))
	defer nodeB.Stop()

	nodeA.AddPeer(nodeB.GetAddr())
	nodeB.AddPeer(nodeA.GetAddr())

	nodeA.Start()
	nodeB.Start()

	nodeA.GenerateKeyPair()
	nodeA.SetPublicID("+33600000000")
	nodeB.GenerateKeyPair()
	nodeB.SetPublicID("+33600000001")

	size := randInt(500)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	chatMsg := types.ChatMessage{Message: hex.EncodeToString(randomBytes)}
	data, err := json.Marshal(&chatMsg)
	require.NoError(t, err)
	nodeB.GenerateKeyPair()
	transpMsg := transport.Message{Payload: data, Type: chatMsg.Name()}
	header := transport.NewHeader(nodeA.GetAddr(), nodeA.GetAddr(), nodeB.GetAddr(), 0)
	pkt := transport.Packet{Header: &header, Msg: &transpMsg}

	nodeAPK := nodeA.GetPK()
	keyBytes, err := x509.MarshalPKIXPublicKey(&nodeAPK)
	require.NoError(t, err)
	nodeB.AddPublicKey(nodeA.GetAddr(), "+33600000000", keyBytes)

	nodeBPK := nodeB.GetPK()
	keyBytes, err = x509.MarshalPKIXPublicKey(&nodeBPK)
	require.NoError(t, err)
	nodeA.AddPublicKey(nodeB.GetAddr(), "+33600000001", keyBytes)

	msg, err := nodeA.EncryptOneToOnePkt(&pkt, nodeB.GetAddr())
	require.NoError(t, err)

	require.NoError(t, nodeA.Unicast(nodeB.GetAddr(), *msg))
	time.Sleep(time.Second * 2)
	require.Equal(t, 1, len(nodeB.GetChatMsgs()))
	require.Equal(t, nodeB.GetChatMsgs()[0].Message, chatMsg.Message)
}

func TestCrypto_Send_Recv_DH_Enc_Msg(t *testing.T) {
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

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	require.NoError(t, nodeA.StartDHKeyExchange(receivers))
	time.Sleep(time.Second)

	size := randInt(500)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	chatMsg := types.ChatMessage{Message: hex.EncodeToString(randomBytes)}
	data, err := json.Marshal(&chatMsg)
	require.NoError(t, err)
	nodeB.GenerateKeyPair()
	trpMsg := transport.Message{Payload: data, Type: chatMsg.Name()}
	header := transport.NewHeader(nodeA.GetAddr(), nodeA.GetAddr(), nodeB.GetAddr(), 0)
	pkt := transport.Packet{Header: &header, Msg: &trpMsg}

	transpMsg, err := nodeA.EncryptDHPkt(&pkt)
	require.NoError(t, err)

	receiversMap := make(map[string]struct{})
	receiversMap[nodeB.GetAddr()] = struct{}{}
	receiversMap[nodeC.GetAddr()] = struct{}{}
	require.NoError(t, nodeA.NaiveMulticast(*transpMsg, receiversMap))
	time.Sleep(time.Second * 2)
	require.Equal(t, 1, len(nodeB.GetChatMsgs()))
	require.Equal(t, chatMsg.Message, nodeB.GetChatMsgs()[0].Message)
	require.Equal(t, 1, len(nodeC.GetChatMsgs()))
	require.Equal(t, chatMsg.Message, nodeC.GetChatMsgs()[0].Message)
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
func TestCrypto_DH_Key_Exchange(t *testing.T) {
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

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

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

	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// B refuses to answer
func TestCrypto_DH_Key_Exchange_Ignoring_Peer(t *testing.T) {
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

	receivers := make(map[string]struct{})
	receivers[socketB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

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

	require.Equal(t, true, nodeA.DHSharedSecretEqual(acadPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))
}

// A,B,C,D,E fully connected
// A starts a key exchange with B,C
// Then D joins
func TestCrypto_DH_Addition(t *testing.T) {
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

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

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

	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))

	err = nodeA.GroupCallAdd(nodeD.GetAddr())
	require.NoError(t, err)

	require.NotEqual(t, nil, nodeD.GetDHSharedSecret())
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// Then C leaves
func TestCrypto_DH_Removal(t *testing.T) {
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

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddr()] = struct{}{}
	receivers[nodeC.GetAddr()] = struct{}{}
	receivers[nodeD.GetAddr()] = struct{}{}
	err := nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

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

	require.Equal(t, true, nodeA.DHSharedSecretEqual(abacadPK))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeC.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))

	nodeA.GroupCallRemove(nodeC.GetAddr())

	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeB.GetDHSharedSecret()))
	require.Equal(t, true, nodeA.DHSharedSecretEqual(nodeD.GetDHSharedSecret()))
	require.NotEqual(t, nil, nodeA.GetDHSharedSecret())
}
