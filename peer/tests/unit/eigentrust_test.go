package unit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
)

// 1 peer, no calls, calculate global trust value
func Test_EigenTrust_No_Calls_1_Peer(t *testing.T) {
	transp := channel.NewTransport()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")

	trustVal, err := node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, trustVal, 0.5)
	node1.Stop()

}

// 2 peers, no rating done, trust value computed based on a priori only
func Test_EigenTrust_No_Calls_3_Peers(t *testing.T) {
	transp := channel.NewTransport()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1))

	trustVal, err := node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.5, trustVal)

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2))

	trustVal2, err := node2.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.25, trustVal2)

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3))

	trustVal3, err := node3.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, float64(1)/float64(6), trustVal3)

	node1.Stop()
	node2.Stop()
	node3.Stop()

}

// 2 peers, node1 calls node2, the other rates good and compute the global trust values for both
func Test_EigenTrust_With_Good_Calls_2_Peers(t *testing.T) {

	transp := channel.NewTransport()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))
	fmt.Println("node1:", node1.GetAddr())
	fmt.Println("node2:", node2.GetAddr())
	fmt.Println("nodeB:", nodeB.GetAddr())

	time.Sleep(time.Second * 2)

	// Simulation of a call
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(nodeB.GetAddr())
	node1.AddPeer(nodeB.GetAddr())

	node1.AddToCallsOutgoingTo(node2.GetAddr())
	node2.AddToCallsIncomingFrom(node1.GetAddr())

	// After a call, node1 gives node2 a good rating
	node2.EigenRatePeer(node1.GetAddr(), 1)

	val, err := node1.ComputeGlobalTrustValue()

	require.NoError(t, err)
	require.Equal(t, 0.75, val)

	defer node1.Stop()
	defer node2.Stop()
}

// 2 peers, 1 calls the other, the other rates bad and compute the global trust values for both

func Test_EigenTrust_With_Bad_Calls_2_Peers(t *testing.T) {
	transp := channel.NewTransport()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2))

	// Simulation of a call
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	node1.AddToCallsOutgoingTo(node2.GetAddr())
	node2.AddToCallsIncomingFrom(node1.GetAddr())

	// After a call, node1 gives node2 a bad rating
	node2.EigenRatePeer(node1.GetAddr(), -1)

	val, err := node1.ComputeGlobalTrustValue()

	require.NoError(t, err)
	require.Equal(t, 0.5, val)

	defer node1.Stop()
	defer node2.Stop()
}

// Calls are made in this order:

// 1 --> 2, 3, 4
//

// Ratings are made in this order:
// 2 --> 1 : good
// 3 --> 1 : good
// 4 --> 1 : bad

func Test_EigenTrust_Multiple_Peers_Good_Calls(t *testing.T) {
	transp := channel.NewTransport()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2))
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3))
	node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(4))

	defer node1.Stop()
	defer node2.Stop()
	defer node3.Stop()
	defer node4.Stop()

}
