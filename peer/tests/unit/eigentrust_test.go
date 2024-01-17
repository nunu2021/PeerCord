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

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))

	time.Sleep(time.Second * 5)

	trustVal, err := node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, trustVal, 0.5)
	node1.Stop()

}

// 2 peers, no rating done, trust value computed based on a priori only
func Test_EigenTrust_No_Calls_3_Peers(t *testing.T) {
	transp := channel.NewTransport()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))

	trustVal, err := node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.5, trustVal)

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))

	trustVal2, err := node2.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.25, trustVal2)

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))

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

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))

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
// 2 --> 5, 6
// 4 --> 1, 6

// Ratings are made in this order:
// 2 --> 1 : good
// 3 --> 1 : good
// 4 --> 1 : bad
// 5 --> 2 : bad
// 6 --> 2 : bad
// 1 --> 4 : good
// 6 --> 4 : bad

func Test_EigenTrust_Multiple_Peers_Good_Calls_Pulse(t *testing.T) {
	transp := channel.NewTransport()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()
	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeC.Stop()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}))
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3), z.WithBootstrapAddrs([]string{nodeC.GetAddr()}))
	node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(4), z.WithBootstrapAddrs([]string{nodeC.GetAddr()}))
	node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(5), z.WithBootstrapAddrs([]string{nodeC.GetAddr()}))
	node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(6), z.WithBootstrapAddrs([]string{nodeC.GetAddr()}))

	defer node1.Stop()
	defer node2.Stop()
	defer node3.Stop()
	defer node4.Stop()
	defer node5.Stop()
	defer node6.Stop()

	// Simulation of calls
	// making calls 1 --> 2, 3, 4

	node1.AddPeer(node2.GetAddr())
	node1.AddPeer(node3.GetAddr())
	node1.AddPeer(node4.GetAddr())
	node2.AddPeer(node1.GetAddr())
	node3.AddPeer(node1.GetAddr())
	node4.AddPeer(node1.GetAddr())

	node1.AddToCallsOutgoingTo(node2.GetAddr())
	node1.AddToCallsOutgoingTo(node3.GetAddr())
	node1.AddToCallsOutgoingTo(node4.GetAddr())
	node2.AddToCallsIncomingFrom(node1.GetAddr())
	node3.AddToCallsIncomingFrom(node1.GetAddr())
	node4.AddToCallsIncomingFrom(node1.GetAddr())

	// After a call, node1 gives node2 a bad rating
	node2.EigenRatePeer(node1.GetAddr(), 1)
	node3.EigenRatePeer(node1.GetAddr(), 1)
	node4.EigenRatePeer(node1.GetAddr(), -1)

	time.Sleep(time.Second * 60)

	// get trust values and check

	val1, err := node1.GetTrust(node1.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.67, val1)

	// making calls // 2 --> 5, 6

	node2.AddPeer(node5.GetAddr())
	node2.AddPeer(node6.GetAddr())
	node5.AddPeer(node2.GetAddr())
	node6.AddPeer(node2.GetAddr())

	node2.AddToCallsOutgoingTo(node5.GetAddr())
	node2.AddToCallsOutgoingTo(node6.GetAddr())
	node5.AddToCallsIncomingFrom(node2.GetAddr())
	node6.AddToCallsIncomingFrom(node2.GetAddr())

	// After a call, node1 gives node2 a bad rating
	node5.EigenRatePeer(node2.GetAddr(), -1)
	node6.EigenRatePeer(node2.GetAddr(), -1)

	time.Sleep(time.Second * 60)

	// get trust values and check

	// first recheck for node1
	val1, err = node1.GetTrust(node1.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.67, val1)

	// then check for node 2
	val2, err := node1.GetTrust(node1.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.5, val2)

	// making calls from // 4 --> 1, 6

	node4.AddPeer(node1.GetAddr())
	node4.AddPeer(node6.GetAddr())

	node1.AddPeer(node4.GetAddr())
	node6.AddPeer(node4.GetAddr())

	node4.AddToCallsOutgoingTo(node1.GetAddr())
	node4.AddToCallsOutgoingTo(node6.GetAddr())

	node1.AddToCallsIncomingFrom(node4.GetAddr())
	node6.AddToCallsIncomingFrom(node4.GetAddr())

	// rate the call
	node1.EigenRatePeer(node4.GetAddr(), 1)
	node6.EigenRatePeer(node4.GetAddr(), -1)

	time.Sleep(time.Second * 60)

	// first recheck for node1
	val1, err = node1.GetTrust(node1.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.88, val1)

	// recheck for node1
	val2, err = node2.GetTrust(node2.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.3, val2)

	// check for node 4
	val4, err := node4.GetTrust(node4.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.3, val4)

}
