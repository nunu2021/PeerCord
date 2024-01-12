package unit

import (
	"testing"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
)

// Tests I need :

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

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:1", z.WithTotalPeers(2))

	trustVal2, err := node2.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.25, trustVal2)

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:2", z.WithTotalPeers(3))

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
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:1", z.WithTotalPeers(2))

	// Simulation of a call
	node1.AddPeer("127.0.0.1:1")
	node2.AddPeer("127.0.0.1:0")

	node1.AddToCallsOutgoingTo("127.0.0.1:1")
	node2.AddToCallsIncomingFrom("127.0.0.1:0")

	// After a call, node1 gives node2 a good rating
	node2.EigenRatePeer("127.0.0.1:0", 1)

	val, err := node1.ComputeGlobalTrustValue()

	require.NoError(t, err)
	require.Equal(t, 1, val)

	defer node1.Stop()
	defer node2.Stop()
}

// 2 peers, 1 calls the other, the other rates bad and compute the global trust values for both

func Test_EigenTrust_With_Bad_Calls_2_Peers(t *testing.T) {
	transp := channel.NewTransport()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:1", z.WithTotalPeers(2))

	// Simulation of a call
	node1.AddPeer("127.0.0.1:1")
	node2.AddPeer("127.0.0.1:0")

	node1.AddToCallsOutgoingTo("127.0.0.1:1")
	node2.AddToCallsIncomingFrom("127.0.0.1:0")

	// After a call, node1 gives node2 a bad rating
	node2.EigenRatePeer("127.0.0.1:0", -1)

	val, err := node1.ComputeGlobalTrustValue()

	require.NoError(t, err)
	require.Equal(t, 0.5, val)

	defer node1.Stop()
	defer node2.Stop()
}
