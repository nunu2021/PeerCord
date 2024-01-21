package unit

import (
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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

	trustVal, err := node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.5, trustVal)

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

	trustVal2, err := node2.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.25, trustVal2)

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

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
	// transp := channel.NewTransport()
	transp := udpFac()

    nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(4), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(5), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())
	node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(6), z.WithBootstrapAddrs([]string{nodeB.GetAddr()}), z.WithStartTrust())

	defer node1.Stop()
	defer node2.Stop()
	defer node3.Stop()
	defer node4.Stop()
	defer node5.Stop()
	defer node6.Stop()

	val1, err := node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.5, val1)

	val2, err := node2.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.25, val2)

	val3, err := node3.ComputeGlobalTrustValue()
	require.NoError(t, err)
	exp := 1.0 / 6.0
	require.Equal(t, exp, val3)

	val4, err := node4.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.125, val4)

	val5, err := node5.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.1, val5)

	val6, err := node6.ComputeGlobalTrustValue()
	require.NoError(t, err)
	exp = 1.0 / 12.0
	require.Equal(t, exp, val6)

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
	// time.Sleep(time.Second * 10)

	// get trust values and check

	val1, err = node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.7083333333333333, val1)

	// // making calls // 2 --> 5, 6

	node2.AddPeer(node5.GetAddr())
	node2.AddPeer(node6.GetAddr())
	node5.AddPeer(node2.GetAddr())
	node6.AddPeer(node2.GetAddr())

	node2.AddToCallsOutgoingTo(node5.GetAddr())
	node2.AddToCallsOutgoingTo(node6.GetAddr())
	node5.AddToCallsIncomingFrom(node2.GetAddr())
	node6.AddToCallsIncomingFrom(node2.GetAddr())

	// // After a call, node1 gives node2 a bad rating
	node5.EigenRatePeer(node2.GetAddr(), -1)
	node6.EigenRatePeer(node2.GetAddr(), -1)

	// time.Sleep(time.Second * 10)

	// get trust values and check

	// first recheck for node1
	val1, err = node1.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.7083333333333333, val1)

	// then check for node 2
	val2, err = node2.ComputeGlobalTrustValue()
	require.NoError(t, err)
	require.Equal(t, 0.25, val2)

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

	// now the pulse can calculate

	// now the pulse can calculate

	// first recheck for node1
	val1, err = node1.GetTrust(node1.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.7083333333333333, val1)

	// recheck for node1
	val2, err = node2.GetTrust(node2.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.25, val2)

	// check for node 4
	val4, err = node4.GetTrust(node4.GetAddr())
	require.NoError(t, err)
	require.Equal(t, 0.47916666666666663, val4)

}

// func Test_EigenTrust_Multiple_Peers_Good_Calls_Pulse(t *testing.T) {
// 	transp := udpFac()

// 	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB.Stop()
// 	nodeC := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeC.Stop()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(1), z.WithBootstrapAddrs([]string{nodeB.GetAddr(), nodeC.GetAddr()}), z.WithStartTrust())
// 	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(2), z.WithBootstrapAddrs([]string{nodeB.GetAddr(), nodeC.GetAddr()}), z.WithStartTrust())
// 	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(3), z.WithBootstrapAddrs([]string{nodeB.GetAddr(), nodeC.GetAddr()}), z.WithStartTrust())
// 	node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(4), z.WithBootstrapAddrs([]string{nodeB.GetAddr(), nodeC.GetAddr()}), z.WithStartTrust())
// 	node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(5), z.WithBootstrapAddrs([]string{nodeB.GetAddr(), nodeC.GetAddr()}), z.WithStartTrust())
// 	node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(6), z.WithBootstrapAddrs([]string{nodeB.GetAddr(), nodeC.GetAddr()}), z.WithStartTrust())

// 	defer node1.Stop()
// 	defer node2.Stop()
// 	defer node3.Stop()
// 	defer node4.Stop()
// 	defer node5.Stop()
// 	defer node6.Stop()

//     fmt.Println("Node 1 Computing value")
// 	val1, err := node1.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.5, val1)

//     fmt.Println("Node 2 Computing value")
// 	val2, err := node2.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.25, val2)

//     fmt.Println("Node 3 Computing value")
// 	val3, err := node3.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	exp := 1.0 / 6.0
// 	require.Equal(t, exp, val3)

//     fmt.Println("Node 4 Computing value")
// 	val4, err := node4.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.125, val4)

//     fmt.Println("Node 5 Computing value")
// 	val5, err := node5.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.1, val5)

//     fmt.Println("Node 6 Computing value")
// 	val6, err := node6.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	exp = 1.0 / 12.0
// 	require.Equal(t, exp, val6)

// 	// Simulation of calls
// 	// making calls 1 --> 2, 3, 4

// 	node1.AddPeer(node2.GetAddr())
// 	node1.AddPeer(node3.GetAddr())
// 	node1.AddPeer(node4.GetAddr())
// 	node2.AddPeer(node1.GetAddr())
// 	node3.AddPeer(node1.GetAddr())
// 	node4.AddPeer(node1.GetAddr())

// 	node1.AddToCallsOutgoingTo(node2.GetAddr())
// 	node1.AddToCallsOutgoingTo(node3.GetAddr())
// 	node1.AddToCallsOutgoingTo(node4.GetAddr())
// 	node2.AddToCallsIncomingFrom(node1.GetAddr())
// 	node3.AddToCallsIncomingFrom(node1.GetAddr())
// 	node4.AddToCallsIncomingFrom(node1.GetAddr())

//     fmt.Printf("Node %s has points %s%s", node1.GetAddr(), node1.PointsToString(0), node1.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node2.GetAddr(), node2.PointsToString(0), node2.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node3.GetAddr(), node3.PointsToString(0), node3.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node4.GetAddr(), node4.PointsToString(0), node4.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node5.GetAddr(), node5.PointsToString(0), node5.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node6.GetAddr(), node6.PointsToString(0), node6.PointsToString(1))

// 	// After a call, node1 gives node2 a bad rating
// 	node2.EigenRatePeer(node1.GetAddr(), 1)
// 	node3.EigenRatePeer(node1.GetAddr(), 1)
// 	node4.EigenRatePeer(node1.GetAddr(), -1)
// 	// time.Sleep(time.Second * 10)

// 	// get trust values and check

// 	val1, err = node1.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.7083333333333333, val1)

//     fmt.Printf("Node %s has points %s%s", node1.GetAddr(), node1.PointsToString(0), node1.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node2.GetAddr(), node2.PointsToString(0), node2.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node3.GetAddr(), node3.PointsToString(0), node3.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node4.GetAddr(), node4.PointsToString(0), node4.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node5.GetAddr(), node5.PointsToString(0), node5.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node6.GetAddr(), node6.PointsToString(0), node6.PointsToString(1))

// 	// // making calls // 2 --> 5, 6

// 	node2.AddPeer(node5.GetAddr())
// 	node2.AddPeer(node6.GetAddr())
// 	node5.AddPeer(node2.GetAddr())
// 	node6.AddPeer(node2.GetAddr())

// 	node2.AddToCallsOutgoingTo(node5.GetAddr())
// 	node2.AddToCallsOutgoingTo(node6.GetAddr())
// 	node5.AddToCallsIncomingFrom(node2.GetAddr())
// 	node6.AddToCallsIncomingFrom(node2.GetAddr())

// 	// // After a call, node1 gives node2 a bad rating
// 	node5.EigenRatePeer(node2.GetAddr(), -1)
// 	node6.EigenRatePeer(node2.GetAddr(), -1)

// 	// time.Sleep(time.Second * 10)

// 	// get trust values and check

// 	// first recheck for node1
// 	val1, err = node1.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.7083333333333333, val1)

// 	// then check for node 2
// 	val2, err = node2.ComputeGlobalTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.25, val2)

//     fmt.Printf("Node %s has points %s%s", node1.GetAddr(), node1.PointsToString(0), node1.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node2.GetAddr(), node2.PointsToString(0), node2.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node3.GetAddr(), node3.PointsToString(0), node3.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node4.GetAddr(), node4.PointsToString(0), node4.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node5.GetAddr(), node5.PointsToString(0), node5.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node6.GetAddr(), node6.PointsToString(0), node6.PointsToString(1))

// 	// making calls from // 4 --> 1, 6

// 	node4.AddPeer(node1.GetAddr())
// 	node4.AddPeer(node6.GetAddr())

// 	node1.AddPeer(node4.GetAddr())
// 	node6.AddPeer(node4.GetAddr())

// 	node4.AddToCallsOutgoingTo(node1.GetAddr())
// 	node4.AddToCallsOutgoingTo(node6.GetAddr())

// 	node1.AddToCallsIncomingFrom(node4.GetAddr())
// 	node6.AddToCallsIncomingFrom(node4.GetAddr())

// 	// rate the call
// 	node1.EigenRatePeer(node4.GetAddr(), 1)
// 	node6.EigenRatePeer(node4.GetAddr(), -1)

//     fmt.Printf("Node %s has points %s%s", node1.GetAddr(), node1.PointsToString(0), node1.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node2.GetAddr(), node2.PointsToString(0), node2.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node3.GetAddr(), node3.PointsToString(0), node3.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node4.GetAddr(), node4.PointsToString(0), node4.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node5.GetAddr(), node5.PointsToString(0), node5.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node6.GetAddr(), node6.PointsToString(0), node6.PointsToString(1))

// 	time.Sleep(time.Second * 60)

//     fmt.Printf("Node %s has points %s%s", node1.GetAddr(), node1.PointsToString(0), node1.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node2.GetAddr(), node2.PointsToString(0), node2.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node3.GetAddr(), node3.PointsToString(0), node3.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node4.GetAddr(), node4.PointsToString(0), node4.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node5.GetAddr(), node5.PointsToString(0), node5.PointsToString(1))
//     fmt.Printf("Node %s has points %s%s", node6.GetAddr(), node6.PointsToString(0), node6.PointsToString(1))

// 	// now the pulse can calculate

// 	fmt.Printf("node %s has GlobalTrustValue %f", node1.GetAddr(), node1.GetTrustValue())
// 	fmt.Printf("node %s has GlobalTrustValue %f", node2.GetAddr(), node2.GetTrustValue())
// 	fmt.Printf("node %s has GlobalTrustValue %f", node3.GetAddr(), node3.GetTrustValue())
// 	fmt.Printf("node %s has GlobalTrustValue %f", node4.GetAddr(), node4.GetTrustValue())
// 	fmt.Printf("node %s has GlobalTrustValue %f", node5.GetAddr(), node5.GetTrustValue())
// 	fmt.Printf("node %s has GlobalTrustValue %f", node6.GetAddr(), node6.GetTrustValue())

// 	// first recheck for node1
// 	// val1, err = node1.GetTrust(node1.GetAddr())
// 	// require.NoError(t, err)
// 	val1 = node1.GetTrustValue()
// 	require.Equal(t, 0.7083333333333333, val1)

// 	// recheck for node1
// 	// val2, err = node2.GetTrust(node2.GetAddr())
// 	// require.NoError(t, err)
// 	val2 = node2.GetTrustValue()
// 	require.Equal(t, 0.25, val2)

// 	// check for node 4
// 	// val4, err = node4.GetTrust(node4.GetAddr())
// 	val4 = node4.GetTrustValue()
// 	require.NoError(t, err)
// 	require.Equal(t, 0.47916666666666663, val4)

// }

