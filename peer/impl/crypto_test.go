package impl

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/registry/standard"
	"go.dedis.ch/cs438/transport/udp"
)

func randInt(N int) int {
	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(N)))
	return int(randNum.Int64())
}

func TestCrypto_DH_Enc_Dec(t *testing.T) {
	size := randInt(100000)
	randomBytes := make([]byte, size)
	rand.Read(randomBytes)
	var crypto1 Crypto
	crypto1.GenerateDHCurve()
	privateKey, _ := crypto1.DHCurve.GenerateKey(rand.Reader)
	var crypto2 Crypto
	crypto2.DHSharedSecret = privateKey.PublicKey()
	crypto1.DHSharedSecret = privateKey.PublicKey()
	encryptedMsg, err := crypto1.EncryptDH(randomBytes)
	require.NoError(t, err)
	decryptedMsg, err := crypto2.DecryptDH(encryptedMsg)
	require.NoError(t, err)
	require.Equal(t, string(decryptedMsg), string(randomBytes))
}

func TestCrypto_OtO_Enc_Dec(t *testing.T) {
	size := randInt(446) //Above 446 is too large for rsa key size
	randomBytes := make([]byte, size)
	size, _ = rand.Read(randomBytes)
	t.Logf("bytes size = %v", size)
	var crypto1 Crypto
	err := crypto1.GenerateKeyPair()
	require.NoError(t, err)
	var crypto2 Crypto
	pubKey := crypto1.KeyPair.PublicKey
	tim := time.Now()
	encryptedMsg, err := crypto2.EncryptOneToOne(randomBytes, &pubKey)
	t.Logf("encryption time = %v", time.Since(tim))
	require.NoError(t, err)
	tim = time.Now()
	decryptedMsg, err := crypto1.DecryptOneToOne(encryptedMsg)
	t.Logf("decryption time = %v", time.Since(tim))
	require.NoError(t, err)
	require.Equal(t, string(decryptedMsg), string(randomBytes))
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

	receivers := make([]string, 3)
	receivers[0] = nodeB.GetAddress()
	receivers[1] = nodeC.GetAddress()
	receivers[2] = nodeD.GetAddress()
	err = nodeA.StartDHKeyExchange(receivers)
	require.NoError(t, err)

	time.Sleep(time.Second * 5)

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
