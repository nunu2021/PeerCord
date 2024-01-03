package impl

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/registry/standard"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
	"go.dedis.ch/cs438/types"
)

func randInt(N int) int {
	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(N)))
	return int(randNum.Int64())
}

func TestCrypto_DH_Enc_Dec(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	nodeA.GenerateDHCurve()
	privateKey, _ := nodeA.crypto.DHCurve.GenerateKey(rand.Reader)
	nodeB.crypto.DHSharedSecret = privateKey.PublicKey()
	nodeA.crypto.DHSharedSecret = privateKey.PublicKey()
	encryptedMsg, err := nodeA.EncryptDH(randomBytes)
	require.NoError(t, err)
	decryptedMsg, err := nodeB.DecryptDH(encryptedMsg)
	require.NoError(t, err)
	require.Equal(t, string(decryptedMsg), string(randomBytes))
}

func TestCrypto_DH_Enc_Dec_Wrong_Key(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	nodeA.GenerateDHCurve()
	privateKey, _ := nodeA.crypto.DHCurve.GenerateKey(rand.Reader)
	nodeB.GenerateDHCurve()
	nodeA.crypto.DHSharedSecret = privateKey.PublicKey()
	privateKey, _ = nodeA.crypto.DHCurve.GenerateKey(rand.Reader)
	nodeB.crypto.DHSharedSecret = privateKey.PublicKey()
	encryptedMsg, err := nodeA.EncryptDH(randomBytes)
	require.NoError(t, err)
	_, err = nodeB.DecryptDH(encryptedMsg)
	require.Error(t, err)
}

func TestCrypto_OtO_Enc_Dec(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	size, _ = rand.Read(randomBytes)
	t.Logf("bytes size = %v", size)
	err = nodeA.GenerateKeyPair()
	require.NoError(t, err)
	pubKey := nodeA.crypto.KeyPair.PublicKey
	tim := time.Now()
	keyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	require.NoError(t, err)
	nodeB.crypto.KnownPKs = StrStrMap{Map: make(map[string]StrBytesPair)}
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
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	size, _ = rand.Read(randomBytes)
	t.Logf("bytes size = %v", size)
	err = nodeA.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, nodeB.GenerateKeyPair())
	pubKey := nodeB.crypto.KeyPair.PublicKey
	keyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	require.NoError(t, err)
	nodeB.crypto.KnownPKs = StrStrMap{Map: make(map[string]StrBytesPair)}
	nodeB.AddPublicKey("127.0.0.1:0", "+33600000000", keyBytes)
	encryptedMsg, err := nodeB.EncryptOneToOne(randomBytes, "127.0.0.1:0")
	require.NoError(t, err)
	_, err = nodeA.DecryptOneToOne(encryptedMsg)
	require.Error(t, err)
}

func TestCrypto_Send_Recv_OtO_Enc_Msg(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	defer nodeA.Stop()
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	defer nodeB.Stop()

	nodeA.AddPeer(nodeB.GetAddress())
	nodeB.AddPeer(nodeA.GetAddress())

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
	header := transport.NewHeader(nodeA.GetAddress(), nodeA.GetAddress(), nodeB.GetAddress(), 0)
	pkt := transport.Packet{Header: &header, Msg: &transpMsg}

	nodeAPK := nodeA.GetPK()
	keyBytes, err := x509.MarshalPKIXPublicKey(&nodeAPK)
	require.NoError(t, err)
	nodeB.AddPublicKey(nodeA.GetAddress(), "+33600000000", keyBytes)

	keyBytes, err = x509.MarshalPKIXPublicKey(&nodeB.crypto.KeyPair.PublicKey)
	require.NoError(t, err)
	nodeA.AddPublicKey(nodeB.GetAddress(), "+33600000001", keyBytes)

	msg, err := nodeA.EncryptOneToOnePkt(&pkt, nodeB.GetAddress())
	require.NoError(t, err)

	require.NoError(t, nodeA.Unicast(nodeB.GetAddress(), *msg))
	time.Sleep(time.Second * 2)
	nodeA.logger.Info().Msg(chatMsg.Message)
}

func TestCrypto_Send_Recv_DH_Enc_Msg(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	defer nodeA.Stop()
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	defer nodeB.Stop()
	socketC, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confC := peer.Configuration{Socket: socketC, MessageRegistry: standard.NewRegistry()}
	nodeC := NewPeer(confC).(*node)
	defer nodeC.Stop()

	nodeA.AddPeer(nodeB.GetAddress())
	nodeB.AddPeer(nodeA.GetAddress())
	nodeA.AddPeer(nodeC.GetAddress())
	nodeB.AddPeer(nodeC.GetAddress())
	nodeC.AddPeer(nodeB.GetAddress())
	nodeC.AddPeer(nodeA.GetAddress())

	nodeA.Start()
	nodeB.Start()
	nodeC.Start()

	nodeA.GenerateKeyPair()
	nodeB.GenerateKeyPair()
	nodeC.GenerateKeyPair()

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddress()] = struct{}{}
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
	header := transport.NewHeader(nodeA.GetAddress(), nodeA.GetAddress(), nodeB.GetAddress(), 0)
	pkt := transport.Packet{Header: &header, Msg: &trpMsg}

	transpMsg, err := nodeA.EncryptDHPkt(&pkt)
	require.NoError(t, err)

	receiversMap := make(map[string]struct{})
	receiversMap[nodeB.GetAddress()] = struct{}{}
	receiversMap[nodeC.GetAddress()] = struct{}{}
	require.NoError(t, nodeA.NaiveMulticast(*transpMsg, receiversMap))
	time.Sleep(time.Second * 2)
	nodeA.logger.Info().Msg(chatMsg.Message)
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
func TestCrypto_DH_Key_Exchange(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	defer nodeA.Stop()
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	defer nodeB.Stop()
	socketC, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confC := peer.Configuration{Socket: socketC, MessageRegistry: standard.NewRegistry()}
	nodeC := NewPeer(confC).(*node)
	defer nodeC.Stop()
	socketD, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confD := peer.Configuration{Socket: socketD, MessageRegistry: standard.NewRegistry()}
	nodeD := NewPeer(confD).(*node)
	defer nodeD.Stop()
	nodeA.AddPeer(nodeB.GetAddress())
	nodeA.AddPeer(nodeC.GetAddress())
	nodeA.AddPeer(nodeD.GetAddress())
	nodeB.AddPeer(nodeA.GetAddress())
	nodeB.AddPeer(nodeC.GetAddress())
	nodeB.AddPeer(nodeD.GetAddress())
	nodeC.AddPeer(nodeA.GetAddress())
	nodeC.AddPeer(nodeB.GetAddress())
	nodeC.AddPeer(nodeD.GetAddress())
	nodeD.AddPeer(nodeA.GetAddress())
	nodeD.AddPeer(nodeB.GetAddress())
	nodeD.AddPeer(nodeC.GetAddress())
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()
	nodeD.Start()

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddress()] = struct{}{}
	receivers[nodeD.GetAddress()] = struct{}{}
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	curve := nodeA.crypto.DHCurve
	ab, err := nodeA.crypto.DHPrivateKey.ECDH(nodeB.crypto.DHPublicKey)
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.crypto.DHPrivateKey.ECDH(nodeC.crypto.DHPublicKey)
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.crypto.DHPrivateKey.ECDH(nodeD.crypto.DHPublicKey)
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

	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(abacadPK))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeB.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeC.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeD.crypto.DHSharedSecret))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// B refuses to answer
func TestCrypto_DH_Key_Exchange_Ignoring_Peer(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	defer nodeA.Stop()
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	socketC, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confC := peer.Configuration{Socket: socketC, MessageRegistry: standard.NewRegistry()}
	nodeC := NewPeer(confC).(*node)
	defer nodeC.Stop()
	socketD, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confD := peer.Configuration{Socket: socketD, MessageRegistry: standard.NewRegistry()}
	nodeD := NewPeer(confD).(*node)
	defer nodeD.Stop()
	nodeA.AddPeer(socketB.GetAddress())
	nodeA.AddPeer(nodeC.GetAddress())
	nodeA.AddPeer(nodeD.GetAddress())
	nodeC.AddPeer(nodeA.GetAddress())
	nodeC.AddPeer(socketB.GetAddress())
	nodeC.AddPeer(nodeD.GetAddress())
	nodeD.AddPeer(nodeA.GetAddress())
	nodeD.AddPeer(socketB.GetAddress())
	nodeD.AddPeer(nodeC.GetAddress())
	nodeA.Start()
	nodeC.Start()
	nodeD.Start()

	receivers := make(map[string]struct{})
	receivers[socketB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddress()] = struct{}{}
	receivers[nodeD.GetAddress()] = struct{}{}
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	curve := nodeA.crypto.DHCurve
	ac, err := nodeA.crypto.DHPrivateKey.ECDH(nodeC.crypto.DHPublicKey)
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.crypto.DHPrivateKey.ECDH(nodeD.crypto.DHPublicKey)
	require.NoError(t, err)
	adSK, err := curve.NewPrivateKey(ad)
	require.NoError(t, err)
	acad, err := acSK.ECDH(adSK.PublicKey())
	require.NoError(t, err)
	acadPK, err := curve.NewPublicKey(acad)
	require.NoError(t, err)

	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(acadPK))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeC.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeD.crypto.DHSharedSecret))
}

// A,B,C,D,E fully connected
// A starts a key exchange with B,C
// Then D joins
func TestCrypto_DH_Addition(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	defer nodeA.Stop()
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	defer nodeB.Stop()
	socketC, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confC := peer.Configuration{Socket: socketC, MessageRegistry: standard.NewRegistry()}
	nodeC := NewPeer(confC).(*node)
	defer nodeC.Stop()
	socketD, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confD := peer.Configuration{Socket: socketD, MessageRegistry: standard.NewRegistry()}
	nodeD := NewPeer(confD).(*node)
	defer nodeD.Stop()
	nodeA.AddPeer(nodeB.GetAddress())
	nodeA.AddPeer(nodeC.GetAddress())
	nodeA.AddPeer(nodeD.GetAddress())
	nodeB.AddPeer(nodeA.GetAddress())
	nodeB.AddPeer(nodeC.GetAddress())
	nodeB.AddPeer(nodeD.GetAddress())
	nodeC.AddPeer(nodeA.GetAddress())
	nodeC.AddPeer(nodeB.GetAddress())
	nodeC.AddPeer(nodeD.GetAddress())
	nodeD.AddPeer(nodeA.GetAddress())
	nodeD.AddPeer(nodeB.GetAddress())
	nodeD.AddPeer(nodeC.GetAddress())
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()
	nodeD.Start()

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddress()] = struct{}{}
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	curve := nodeA.crypto.DHCurve
	ab, err := nodeA.crypto.DHPrivateKey.ECDH(nodeB.crypto.DHPublicKey)
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.crypto.DHPrivateKey.ECDH(nodeC.crypto.DHPublicKey)
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	abac, err := abSK.ECDH(acSK.PublicKey())
	require.NoError(t, err)
	abacPK, err := curve.NewPublicKey(abac)
	require.NoError(t, err)

	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(abacPK))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeB.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeC.crypto.DHSharedSecret))

	err = nodeA.GroupCallAdd(nodeD.GetAddress())
	require.NoError(t, err)

	require.NotEqual(t, nil, nodeD.crypto.DHSharedSecret)
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeD.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeB.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeC.crypto.DHSharedSecret))
}

// A,B,C,D fully connected
// A starts a key exchange with B,C,D
// Then C leaves
func TestCrypto_DH_Removal(t *testing.T) {
	udpTransport := udp.NewUDP()
	socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry()}
	nodeA := NewPeer(confA).(*node)
	defer nodeA.Stop()
	socketB, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confB := peer.Configuration{Socket: socketB, MessageRegistry: standard.NewRegistry()}
	nodeB := NewPeer(confB).(*node)
	defer nodeB.Stop()
	socketC, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confC := peer.Configuration{Socket: socketC, MessageRegistry: standard.NewRegistry()}
	nodeC := NewPeer(confC).(*node)
	defer nodeC.Stop()
	socketD, err := udpTransport.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	confD := peer.Configuration{Socket: socketD, MessageRegistry: standard.NewRegistry()}
	nodeD := NewPeer(confD).(*node)
	defer nodeD.Stop()
	nodeA.AddPeer(nodeB.GetAddress())
	nodeA.AddPeer(nodeC.GetAddress())
	nodeA.AddPeer(nodeD.GetAddress())
	nodeB.AddPeer(nodeA.GetAddress())
	nodeB.AddPeer(nodeC.GetAddress())
	nodeB.AddPeer(nodeD.GetAddress())
	nodeC.AddPeer(nodeA.GetAddress())
	nodeC.AddPeer(nodeB.GetAddress())
	nodeC.AddPeer(nodeD.GetAddress())
	nodeD.AddPeer(nodeA.GetAddress())
	nodeD.AddPeer(nodeB.GetAddress())
	nodeD.AddPeer(nodeC.GetAddress())
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()
	nodeD.Start()

	receivers := make(map[string]struct{})
	receivers[nodeB.GetAddress()] = struct{}{}
	receivers[nodeC.GetAddress()] = struct{}{}
	receivers[nodeD.GetAddress()] = struct{}{}
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	curve := nodeA.crypto.DHCurve
	ab, err := nodeA.crypto.DHPrivateKey.ECDH(nodeB.crypto.DHPublicKey)
	require.NoError(t, err)
	abSK, err := curve.NewPrivateKey(ab)
	require.NoError(t, err)
	ac, err := nodeA.crypto.DHPrivateKey.ECDH(nodeC.crypto.DHPublicKey)
	require.NoError(t, err)
	acSK, err := curve.NewPrivateKey(ac)
	require.NoError(t, err)
	ad, err := nodeA.crypto.DHPrivateKey.ECDH(nodeD.crypto.DHPublicKey)
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

	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(abacadPK))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeB.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeC.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeD.crypto.DHSharedSecret))

	nodeA.GroupCallRemove(nodeC.GetAddress())

	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeB.crypto.DHSharedSecret))
	require.Equal(t, true, nodeA.crypto.DHSharedSecret.Equal(nodeD.crypto.DHSharedSecret))
	require.NotEqual(t, nil, nodeA.crypto.DHSharedSecret)
}

func TestCrypto_Perf_DH_Key_Exchange(t *testing.T) {
	udpTransport := udp.NewUDP()

	peers := make([]*node, 0)

	for i := 0; i < 30; i++ {
		socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
		require.NoError(t, err)
		confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry(), HeartbeatInterval: time.Millisecond * 50}
		nodeA := NewPeer(confA).(*node)
		defer nodeA.Stop()
		peers = append(peers, nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 3)
	for _, peer := range peers {
		peer.conf.HeartbeatInterval = 0
	}

	time.Sleep(time.Second * 2)

	for i := 3; i <= 10; i++ {
		times := make([]time.Duration, 0)
		for try := 0; try < 50; try++ {
			members := make([]int, 0)
			for j := 0; j < i; j++ {
				k := randInt(len(peers))
				found := false
				for !found {
					contained := false
					for _, v := range members {
						if v == k {
							contained = true
							break
						}
					}
					if !contained {
						found = true
						members = append(members, k)
					} else {
						k = randInt(len(peers))
					}
				}
			}
			receivers := make(map[string]struct{})
			first := true
			for _, v := range members {
				if first {
					first = false
					continue
				}
				receivers[peers[v].GetAddress()] = struct{}{}
			}
			t := time.Now()
			peers[members[0]].StartDHKeyExchange(receivers)
			times = append(times, time.Since(t))
			for _, v := range members {
				peers[v].GroupCallEnd()
			}
		}
		t.Logf("%v: %v,", i, times)
	}
}

func TestCrypto_Perf_DH_Addition(t *testing.T) {
	udpTransport := udp.NewUDP()

	peers := make([]*node, 0)

	for i := 0; i < 30; i++ {
		socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
		require.NoError(t, err)
		confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry(), HeartbeatInterval: time.Millisecond * 50}
		nodeA := NewPeer(confA).(*node)
		defer nodeA.Stop()
		peers = append(peers, nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 3)
	for _, peer := range peers {
		peer.conf.HeartbeatInterval = 0
	}

	time.Sleep(time.Second * 2)

	for i := 4; i <= 11; i++ {
		times := make([]time.Duration, 0)
		for try := 0; try < 50; try++ {
			members := make([]int, 0)
			for j := 0; j < i; j++ {
				k := randInt(len(peers))
				found := false
				for !found {
					contained := false
					for _, v := range members {
						if v == k {
							contained = true
							break
						}
					}
					if !contained {
						found = true
						members = append(members, k)
					} else {
						k = randInt(len(peers))
					}
				}
			}
			receivers := make(map[string]struct{})
			first := true
			for _, v := range members[:len(members)-1] {
				if first {
					first = false
					continue
				}
				receivers[peers[v].GetAddress()] = struct{}{}
			}
			peers[members[0]].StartDHKeyExchange(receivers)
			t := time.Now()
			peers[members[0]].GroupCallAdd(peers[members[len(members)-1]].GetAddress())
			times = append(times, time.Since(t))
			for _, v := range members {
				peers[v].GroupCallEnd()
			}
		}
		t.Logf("%v: %v,", i-1, times)
	}
}

func TestCrypto_Perf_DH_Removal(t *testing.T) {
	udpTransport := udp.NewUDP()

	peers := make([]*node, 0)

	for i := 0; i < 30; i++ {
		socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
		require.NoError(t, err)
		confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry(), HeartbeatInterval: time.Millisecond * 50}
		nodeA := NewPeer(confA).(*node)
		defer nodeA.Stop()
		peers = append(peers, nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 3)
	for _, peer := range peers {
		peer.conf.HeartbeatInterval = 0
	}

	time.Sleep(time.Second * 2)

	for i := 3; i <= 10; i++ {
		times := make([]time.Duration, 0)
		for try := 0; try < 50; try++ {
			members := make([]int, 0)
			for j := 0; j < i; j++ {
				k := randInt(len(peers))
				found := false
				for !found {
					contained := false
					for _, v := range members {
						if v == k {
							contained = true
							break
						}
					}
					if !contained {
						found = true
						members = append(members, k)
					} else {
						k = randInt(len(peers))
					}
				}
			}
			receivers := make(map[string]struct{})
			first := true
			for _, v := range members {
				if first {
					first = false
					continue
				}
				receivers[peers[v].GetAddress()] = struct{}{}
			}
			peers[members[0]].StartDHKeyExchange(receivers)
			t := time.Now()
			peers[members[0]].GroupCallRemove(peers[members[len(members)-1]].GetAddress())
			times = append(times, time.Since(t))
			for _, v := range members {
				peers[v].GroupCallEnd()
			}
		}
		t.Logf("%v: %v,", i, times)
	}
}

func TestCrypto_Perf_DH_Key_Exchange_Network_Size(t *testing.T) {
	udpTransport := udp.NewUDP()

	size := 10

	peers := make([]*node, 0)

	for i := 0; i < size; i++ {
		socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
		require.NoError(t, err)
		confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry(), HeartbeatInterval: time.Millisecond * 50}
		nodeA := NewPeer(confA).(*node)
		defer nodeA.Stop()
		peers = append(peers, nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 3)
	for _, peer := range peers {
		peer.conf.HeartbeatInterval = 0
	}

	time.Sleep(time.Second * 2)

	times := make([]time.Duration, 0)
	for try := 0; try < 50; try++ {
		members := make([]int, 0)
		for j := 0; j < 7; j++ {
			k := randInt(len(peers))
			found := false
			for !found {
				contained := false
				for _, v := range members {
					if v == k {
						contained = true
						break
					}
				}
				if !contained {
					found = true
					members = append(members, k)
				} else {
					k = randInt(len(peers))
				}
			}
		}
		receivers := make(map[string]struct{})
		first := true
		for _, v := range members {
			if first {
				first = false
				continue
			}
			receivers[peers[v].GetAddress()] = struct{}{}
		}
		ti := time.Now()
		peers[members[0]].StartDHKeyExchange(receivers)
		times = append(times, time.Since(ti))
		for _, v := range members {
			peers[v].GroupCallEnd()
		}
	}
	t.Logf("%v: %v,", size, times)
}
func TestCrypto_Perf_DH_Addition_Network_Size(t *testing.T) {
	udpTransport := udp.NewUDP()

	size := 60

	peers := make([]*node, 0)

	for i := 0; i < size; i++ {
		socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
		require.NoError(t, err)
		confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry(), HeartbeatInterval: time.Millisecond * 50}
		nodeA := NewPeer(confA).(*node)
		defer nodeA.Stop()
		peers = append(peers, nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 3)
	for _, peer := range peers {
		peer.conf.HeartbeatInterval = 0
	}

	time.Sleep(time.Second * 2)

	times := make([]time.Duration, 0)
	for try := 0; try < 50; try++ {
		members := make([]int, 0)
		for j := 0; j < 7; j++ {
			k := randInt(len(peers))
			found := false
			for !found {
				contained := false
				for _, v := range members {
					if v == k {
						contained = true
						break
					}
				}
				if !contained {
					found = true
					members = append(members, k)
				} else {
					k = randInt(len(peers))
				}
			}
		}
		receivers := make(map[string]struct{})
		first := true
		for _, v := range members[:len(members)-1] {
			if first {
				first = false
				continue
			}
			receivers[peers[v].GetAddress()] = struct{}{}
		}
		peers[members[0]].StartDHKeyExchange(receivers)
		t := time.Now()
		peers[members[0]].GroupCallAdd(peers[members[len(members)-1]].GetAddress())
		times = append(times, time.Since(t))
		for _, v := range members {
			peers[v].GroupCallEnd()
		}
	}
	t.Logf("%v: %v,", size-1, times)
}

func TestCrypto_Perf_DH_Removal_Network_Size(t *testing.T) {
	udpTransport := udp.NewUDP()

	size := 60

	peers := make([]*node, 0)

	for i := 0; i < size; i++ {
		socketA, err := udpTransport.CreateSocket("127.0.0.1:0")
		require.NoError(t, err)
		confA := peer.Configuration{Socket: socketA, MessageRegistry: standard.NewRegistry(), HeartbeatInterval: time.Millisecond * 50}
		nodeA := NewPeer(confA).(*node)
		defer nodeA.Stop()
		peers = append(peers, nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 3)
	for _, peer := range peers {
		peer.conf.HeartbeatInterval = 0
	}

	time.Sleep(time.Second * 2)

	times := make([]time.Duration, 0)
	for try := 0; try < 50; try++ {
		members := make([]int, 0)
		for j := 0; j < 7; j++ {
			k := randInt(len(peers))
			found := false
			for !found {
				contained := false
				for _, v := range members {
					if v == k {
						contained = true
						break
					}
				}
				if !contained {
					found = true
					members = append(members, k)
				} else {
					k = randInt(len(peers))
				}
			}
		}
		receivers := make(map[string]struct{})
		first := true
		for _, v := range members {
			if first {
				first = false
				continue
			}
			receivers[peers[v].GetAddress()] = struct{}{}
		}
		peers[members[0]].StartDHKeyExchange(receivers)
		t := time.Now()
		peers[members[0]].GroupCallRemove(peers[members[len(members)-1]].GetAddress())
		times = append(times, time.Since(t))
		for _, v := range members {
			peers[v].GroupCallEnd()
		}
	}
	t.Logf("%v: %v,", size, times)
}

// Generate randomly adds peers to nodes. It makes sure the graph is connected
// without orphans.
func GenerateRandomGraph(peers []*node) {

	addrToPeer := make(map[string]*node)
	for _, peer := range peers {
		addrToPeer[peer.GetAddress()] = peer
	}

	peersNeighboors := make(map[string][]string)

	for i := 1; i < len(peers); i++ {

		connected := false
		for !connected {
			for j := 0; j < i; j++ {
				if mrand.Float64() >= 0.2 {
					continue
				}

				connected = true

				peersNeighboors[peers[j].GetAddress()] = append(peersNeighboors[peers[j].GetAddress()], peers[i].GetAddress())
				peersNeighboors[peers[i].GetAddress()] = append(peersNeighboors[peers[i].GetAddress()], peers[j].GetAddress())
			}
		}
	}

	for k, v := range peersNeighboors {
		addrToPeer[k].AddPeer(v...)
	}
}
