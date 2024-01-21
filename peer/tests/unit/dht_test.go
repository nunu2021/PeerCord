package unit

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	// "go.dedis.ch/cs438/transport/channel"
	// "go.dedis.ch/cs438/types"
)

// Uncomment for testing
//
// Most of the testing must be done through printing, therefore
// all of the tests that require printing are commented out
//
// Uncomment them, "fmt", and the functions in the "CAN" interface
// to test them
//
// The CAN interface functions are commented out due to the linter

// func Test_DHT_Bootstrap_Empty(t *testing.T) {
// 	transp := channel.NewTransport()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer node1.Stop()

//     require.Equal(t, true, node1.GetBootstrap())
//     require.Len(t, node1.GetNodeList(), 0)
// }



// func Test_DHT_Bootstrap_Single(t *testing.T) {
// 	transp := channel.NewTransport()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer node1.Stop()

//     require.Equal(t, true, node1.GetBootstrap())
//     node1.AddNodeBootstrap("127.0.0.1:1")

//     require.Len(t, node1.GetNodeList(), 1)
// }



// func Test_DHT_Bootstrap_Many(t *testing.T) {
// 	transp := channel.NewTransport()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer node1.Stop()

//     require.Equal(t, true, node1.GetBootstrap())

// 	node1.AddNodeBootstrap("127.0.0.1:1")
// 	node1.AddNodeBootstrap("127.0.0.1:2")
// 	node1.AddNodeBootstrap("127.0.0.1:3")
// 	node1.AddNodeBootstrap("127.0.0.1:4")
// 	node1.AddNodeBootstrap("127.0.0.1:5")
// 	node1.AddNodeBootstrap("127.0.0.1:6")
// 	node1.AddNodeBootstrap("127.0.0.1:7")
// 	node1.AddNodeBootstrap("127.0.0.1:8")
// 	node1.AddNodeBootstrap("127.0.0.1:9")
// 	node1.AddNodeBootstrap("127.0.0.1:10")
// 	node1.AddNodeBootstrap("127.0.0.1:11")

//     require.Len(t, node1.GetNodeList(), node1.GetNodeLimit())
// }



// func Test_DHT_No_Bootstrap(t *testing.T) {
// 	transp := channel.NewTransport()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
// 	defer node1.Stop()

//     require.Equal(t, false, node1.GetBootstrap())
//     require.Len(t, node1.GetNodeList(), 0)

// 	node1.AddNodeBootstrap("127.0.0.1:1")
//     require.Len(t, node1.GetNodeList(), 0)
// }


// func Test_DHT_Hash(t *testing.T) {
// 	transp := channel.NewTransport()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
// 	defer node1.Stop()

//     p := node1.Hash("0.0.0.0:0")
//     pSol := types.Point([]uint16{0, 0, 0})
//     require.Equal(t, pSol, p)

//     p = node1.Hash("10.5.2.100:567")
//     pSol = types.Point([]uint16{2660, 1282, 567})
//     require.Equal(t, pSol, p)
// }

// func Test_DHT_Overlap1D(t *testing.T) {
// 	transp := channel.NewTransport()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
// 	defer node1.Stop()

//     require.Equal(t, false, node1.Overlap1D(0, 10, 14, 19))
//     require.Equal(t, false, node1.Overlap1D(0, 10, 12, 19))
//     require.Equal(t, true, node1.Overlap1D(0, 10, 11, 19))
//     require.Equal(t, true, node1.Overlap1D(0, 10, 4, 19))
//     require.Equal(t, true, node1.Overlap1D(0, 10, 4, 9))
//     require.Equal(t, true, node1.Overlap1D(10, 15, 4, 9))
//     require.Equal(t, false, node1.Overlap1D(10, 15, 4, 8))
// }


// func Test_DHT_BordersZone(t *testing.T) {
// 	transp := channel.NewTransport()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
// 	defer node1.Stop()

//     zone1 := types.Zone{
//         LowerLeft: types.Point([]uint16{0, 0, 0}),
//         UpperRight: types.Point([]uint16{10, 10, 10}),
//     }
//     zone2 := types.Zone{
//         LowerLeft: types.Point([]uint16{11, 0, 0}),
//         UpperRight: types.Point([]uint16{20, 11, 11}),
//     }
//     zone3 := types.Zone{
//         LowerLeft: types.Point([]uint16{15, 11, 11}),
//         UpperRight: types.Point([]uint16{16, 12, 12}),
//     }
//     zone4 := types.Zone{
//         LowerLeft: types.Point([]uint16{45, 14, 45}),
//         UpperRight: types.Point([]uint16{66, 19, 56}),
//     }

//     require.Equal(t, true, node1.BordersZone(zone1, zone2))
//     require.Equal(t, true, node1.BordersZone(zone2, zone3))
//     require.Equal(t, false, node1.BordersZone(zone1, zone3))
//     require.Equal(t, false, node1.BordersZone(zone1, zone4))
//     require.Equal(t, false, node1.BordersZone(zone2, zone4))
//     require.Equal(t, false, node1.BordersZone(zone3, zone4))
// }

// func Test_DHT_Query_Bootstrap_Simple(t *testing.T) {
// 	transp := channel.NewTransport()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer node1.Stop()

//     node1Addr := node1.GetAddr()

//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node2.Stop()

// 	node2.AddPeer(node1.GetAddr())

//     require.Len(t, node2.GetRoutingTable(), 2)

//     err := node2.JoinDHT()

//     require.NoError(t, err)
//     require.Len(t, node1.GetRoutingTable(), 2)

//     zone := types.Zone{
//         LowerLeft: types.Point([]uint16{0, 0, 0}),
//         UpperRight: types.Point([]uint16{0xFFFF, 0xFFFF, 0xFFFF}),
//     }

//     for i := 0; i < 5; i++ {
//         require.Equal(t, zone, node2.ReturnDHTArea(i))

//         require.Len(t, node2.ReturnDHTNeighbors(i), 0)
//         require.Len(t, node2.ReturnDHTPoints(i), 0)
//     }

//     bNodes := node1.ReturnBootstrapNodes()
//     require.Len(t, bNodes, 1)
//     require.Equal(t, node2.GetAddr(), bNodes[0])
// }


// func Test_DHT_Query_Bootstrap_Many(t *testing.T) {
// 	transp := channel.NewTransport()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer node1.Stop()

//     node1Addr := node1.GetAddr()

//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node2.Stop()
//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node3.Stop()
//     node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node4.Stop()

// 	node2.AddPeer(node1.GetAddr())
// 	node3.AddPeer(node1.GetAddr())
// 	node4.AddPeer(node1.GetAddr())

//     time.Sleep(time.Second)

//     require.Len(t, node1.GetRoutingTable(), 4)
//     require.Len(t, node2.GetRoutingTable(), 4)
//     require.Len(t, node3.GetRoutingTable(), 4)
//     require.Len(t, node4.GetRoutingTable(), 4)

//     bNodes := node1.ReturnBootstrapNodes()
//     fmt.Println(bNodes)
//     require.Len(t, bNodes, 3)
//     require.Equal(t, node2.GetAddr(), bNodes[0])
//     require.Equal(t, node3.GetAddr(), bNodes[1])
//     require.Equal(t, node4.GetAddr(), bNodes[2])
// }


// func Test_DHT_Zone_Division_5_Nodes_With_Sleep(t *testing.T) {
// 	transp := channel.NewTransport()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer node1.Stop()

//     fmt.Printf("Bootstrap node address: node 1 - %s\n", node1.GetAddr())

//     node1Addr := node1.GetAddr()

//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node2.Stop()
//     time.Sleep(time.Second * 4)

//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node3.Stop()
//     time.Sleep(time.Second * 4)

//     node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node4.Stop()
//     time.Sleep(time.Second * 4)

//     node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node5.Stop()
//     time.Sleep(time.Second * 4)

//     node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
// 	defer node6.Stop()
//     time.Sleep(time.Second * 4)

//     for i := 0; i < 5; i++ {
//         node2Area := node2.ReturnDHTArea(i)
//         node3Area := node3.ReturnDHTArea(i)
//         node4Area := node4.ReturnDHTArea(i)
//         node5Area := node5.ReturnDHTArea(i)
//         node6Area := node6.ReturnDHTArea(i)

//         node2Neighbors := node2.NeighborsToStringLocked(i)
//         node3Neighbors := node3.NeighborsToStringLocked(i)
//         node4Neighbors := node4.NeighborsToStringLocked(i)
//         node5Neighbors := node5.NeighborsToStringLocked(i)
//         node6Neighbors := node6.NeighborsToStringLocked(i)

//         fmt.Printf("Node 2, reality %d --\nArea: %s\n%s\n", i, node2Area.String(), node2Neighbors)
//         fmt.Printf("Node 3, reality %d --\nArea: %s\n%s\n", i, node3Area.String(), node3Neighbors)
//         fmt.Printf("Node 4, reality %d --\nArea: %s\n%s\n", i, node4Area.String(), node4Neighbors)
//         fmt.Printf("Node 5, reality %d --\nArea: %s\n%s\n", i, node5Area.String(), node5Neighbors)
//         fmt.Printf("Node 6, reality %d --\nArea: %s\n%s\n", i, node6Area.String(), node6Neighbors)
//     }
// }


// func Test_DHT_Zone_Division_12_Nodes(t *testing.T) {
// 	transp := channel.NewTransport()

// 	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB.Stop()

//     nodeBAddr := nodeB.GetAddr()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node1.Stop()
//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node2.Stop()
//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node3.Stop()
//     node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node4.Stop()
//     node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node5.Stop()
//     node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node6.Stop()
//     node7 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node7.Stop()
//     node8 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node8.Stop()
//     node9 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node9.Stop()
//     node10 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node10.Stop()
//     node11 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node11.Stop()
//     node12 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node12.Stop()

//     time.Sleep(time.Second * 10)

//     for i := 0; i < 5; i++ {
//         node1Area := node1.ReturnDHTSequencedArea(i)
//         node2Area := node2.ReturnDHTSequencedArea(i)
//         node3Area := node3.ReturnDHTSequencedArea(i)
//         node4Area := node4.ReturnDHTSequencedArea(i)
//         node5Area := node5.ReturnDHTSequencedArea(i)
//         node6Area := node6.ReturnDHTSequencedArea(i)
//         node7Area := node7.ReturnDHTSequencedArea(i)
//         node8Area := node8.ReturnDHTSequencedArea(i)
//         node9Area := node9.ReturnDHTSequencedArea(i)
//         node10Area := node10.ReturnDHTSequencedArea(i)
//         node11Area := node11.ReturnDHTSequencedArea(i)
//         node12Area := node12.ReturnDHTSequencedArea(i)

//         fmt.Printf("Node 2, reality %d --\nArea: %s\n%s\n", i, node1Area.String(), node1.NeighborsToStringLocked(i))
//         fmt.Printf("Node 3, reality %d --\nArea: %s\n%s\n", i, node2Area.String(), node2.NeighborsToStringLocked(i))
//         fmt.Printf("Node 4, reality %d --\nArea: %s\n%s\n", i, node3Area.String(), node3.NeighborsToStringLocked(i))
//         fmt.Printf("Node 5, reality %d --\nArea: %s\n%s\n", i, node4Area.String(), node4.NeighborsToStringLocked(i))
//         fmt.Printf("Node 6, reality %d --\nArea: %s\n%s\n", i, node5Area.String(), node5.NeighborsToStringLocked(i))
//         fmt.Printf("Node 7, reality %d --\nArea: %s\n%s\n", i, node6Area.String(), node6.NeighborsToStringLocked(i))
//         fmt.Printf("Node 8, reality %d --\nArea: %s\n%s\n", i, node7Area.String(), node7.NeighborsToStringLocked(i))
//         fmt.Printf("Node 9, reality %d --\nArea: %s\n%s\n", i, node8Area.String(), node8.NeighborsToStringLocked(i))
//         fmt.Printf("Node 10, reality %d --\nArea: %s\n%s\n", i, node9Area.String(), node8.NeighborsToStringLocked(i))
//         fmt.Printf("Node 11, reality %d --\nArea: %s\n%s\n", i, node10Area.String(), node8.NeighborsToStringLocked(i))
//         fmt.Printf("Node 12, reality %d --\nArea: %s\n%s\n", i, node11Area.String(), node8.NeighborsToStringLocked(i))
//         fmt.Printf("Node 13, reality %d --\nArea: %s\n%s\n", i, node12Area.String(), node8.NeighborsToStringLocked(i))
//     }
// }

// func Test_DHT_Multiple_Bootstrap(t *testing.T) {
// 	transp := channel.NewTransport()

// 	nodeB1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB1.Stop()
// 	nodeB2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB2.Stop()
// 	nodeB3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB3.Stop()
// 	nodeB4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB4.Stop()

//     nodeB1Addr := nodeB1.GetAddr()
//     nodeB2Addr := nodeB2.GetAddr()
//     nodeB3Addr := nodeB3.GetAddr()
//     nodeB4Addr := nodeB4.GetAddr()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeB1Addr, nodeB2Addr, nodeB3Addr, nodeB4Addr}))
// 	defer node1.Stop()
//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeB1Addr, nodeB2Addr, nodeB3Addr, nodeB4Addr}))
// 	defer node2.Stop()
//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeB1Addr, nodeB2Addr, nodeB3Addr, nodeB4Addr}))
// 	defer node3.Stop()

// 	time.Sleep(time.Second * 2)

//     for i := 0; i < 5; i++ {
//         node1Area := node1.ReturnDHTSequencedArea(i)
//         node2Area := node2.ReturnDHTSequencedArea(i)
//         node3Area := node3.ReturnDHTSequencedArea(i)

//         fmt.Printf("Node 5, reality %d --\nArea: %s\n%s\n", i, node1Area.String(), node1.NeighborsToStringLocked(i))
//         fmt.Printf("Node 6, reality %d --\nArea: %s\n%s\n", i, node2Area.String(), node2.NeighborsToStringLocked(i))
//         fmt.Printf("Node 7, reality %d --\nArea: %s\n%s\n", i, node3Area.String(), node3.NeighborsToStringLocked(i))
//     }
// }

// func Test_DHT_Set_Trust_Value(t *testing.T) {
// 	transp := channel.NewTransport()

// 	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB.Stop()

//     nodeBAddr := nodeB.GetAddr()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node1.Stop()
//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node2.Stop()
//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node3.Stop()

// 	time.Sleep(time.Second * 2)

//     fmt.Printf("Hash of 643.764.23.75:44: %v\n", nodeB.Hash("643.764.23.75:44").String())
//     err := node1.SetTrust(node1.GetAddr(), 5.5)
//     require.NoError(t, err)
//     err = node1.SetTrust("643.764.23.75:44", 5.8)
//     require.NoError(t, err)
//     err = node1.SetTrust(node3.GetAddr(), 5134.0)
//     require.NoError(t, err)
//     err = node1.SetTrust(node1.GetAddr(), 67.3)
//     require.NoError(t, err)

// 	time.Sleep(time.Second * 1)

//     for i := 0; i < 5; i++ {
//         node1Area := node1.ReturnDHTSequencedArea(i)
//         node2Area := node2.ReturnDHTSequencedArea(i)
//         node3Area := node3.ReturnDHTSequencedArea(i)

//         fmt.Printf("Node 2, reality %d --\nArea: %s\n%s\n%s\n", i, node1Area.String(), node1.NeighborsToStringLocked(i), node1.PointsToString(i))
//         fmt.Printf("Node 3, reality %d --\nArea: %s\n%s\n%s\n", i, node2Area.String(), node2.NeighborsToStringLocked(i), node2.PointsToString(i))
//         fmt.Printf("Node 4, reality %d --\nArea: %s\n%s\n%s\n", i, node3Area.String(), node3.NeighborsToStringLocked(i), node3.PointsToString(i))
//     }
// }


// func Test_DHT_Get_Trust_Value(t *testing.T) {
// 	transp := channel.NewTransport()

// 	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB.Stop()

//     nodeBAddr := nodeB.GetAddr()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node1.Stop()
//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node2.Stop()
//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node3.Stop()

// 	time.Sleep(time.Second * 2)

//     trust1 := 5.5
//     trust2 := 25.567
//     trust3 := 234.0

//     err := node2.SetTrust(node1.GetAddr(), trust1)
//     require.NoError(t, err)
//     err = node1.SetTrust(node3.GetAddr(), trust3)
//     require.NoError(t, err)
//     err = node3.SetTrust(node2.GetAddr(), trust2)
//     require.NoError(t, err)

// 	time.Sleep(time.Second * 1)

//     trustResponse1, err := node1.GetTrust(node1.GetAddr())
//     require.NoError(t, err)
//     require.Equal(t, trust1, trustResponse1)

//     trustResponse2, err := node2.GetTrust(node2.GetAddr())
//     require.NoError(t, err)
//     require.Equal(t, trust2, trustResponse2)

//     trustResponse3, err := node3.GetTrust(node3.GetAddr())
//     require.NoError(t, err)
//     require.Equal(t, trust3, trustResponse3)
// }


// func Test_DHT_Split_Trusts(t *testing.T) {
// 	transp := channel.NewTransport()

// 	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
// 	defer nodeB.Stop()

//     nodeBAddr := nodeB.GetAddr()

//     node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node1.Stop()

// 	time.Sleep(time.Second * 1)

//     // fmt.Printf("Hash of 643.764.23.75:44: %v\n", nodeB.Hash("643.764.23.75:44").String())
//     // fmt.Printf("Hash of 17.47.242.59:3253: %v\n", nodeB.Hash("17.47.242.59:3253").String())
//     // fmt.Printf("Hash of 206.97.54.49:43: %v\n", nodeB.Hash("206.97.54.49:43").String())
//     // fmt.Printf("Hash of 785.197.193.203:3884: %v\n", nodeB.Hash("785.197.193.203:3884").String())
//     // fmt.Printf("Hash of 232.132.61.226:4: %v\n", nodeB.Hash("232.132.61.226:4").String())
//     // fmt.Printf("Hash of 5.38.10.20:23: %v\n", nodeB.Hash("5.38.10.20:23").String())

//     err := node1.SetTrust("643.764.23.75:44", 2546)
//     require.NoError(t, err)
//     err = node1.SetTrust("17.47.242.59:3253", 5.8)
//     require.NoError(t, err)
//     err = node1.SetTrust("206.97.54.49:43", 8.245)
//     require.NoError(t, err)
//     err = node1.SetTrust("785.197.193.203:3884", 72.2)
//     require.NoError(t, err)
//     err = node1.SetTrust("232.132.61.226:4", 2.887)
//     require.NoError(t, err)
//     err = node1.SetTrust("5.38.10.20:23", 644.3)
//     require.NoError(t, err)

// 	time.Sleep(time.Second * 2)

//     node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node2.Stop()
//     node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
// 	defer node3.Stop()

// 	time.Sleep(time.Second)

//     for i := 0; i < 5; i++ {
//         node1Area := node1.ReturnDHTSequencedArea(i)
//         node2Area := node2.ReturnDHTSequencedArea(i)
//         node3Area := node3.ReturnDHTSequencedArea(i)

//         fmt.Printf("Node 2, reality %d --\nArea: %s\n%s\n%s\n", i, node1Area.String(), node1.NeighborsToStringLocked(i), node1.PointsToString(i))
//         fmt.Printf("Node 3, reality %d --\nArea: %s\n%s\n%s\n", i, node2Area.String(), node2.NeighborsToStringLocked(i), node2.PointsToString(i))
//         fmt.Printf("Node 4, reality %d --\nArea: %s\n%s\n%s\n", i, node3Area.String(), node3.NeighborsToStringLocked(i), node3.PointsToString(i))
//     }
// }

        // err := node1.SetTrust("643.764.23.75:44", 2546)
        // require.NoError(t, err)
        // err = node1.SetTrust("17.47.242.59:3253", 5.8)
        // require.NoError(t, err)
        // err = node1.SetTrust("206.97.54.49:43", 8.245)
        // require.NoError(t, err)
        // err = node1.SetTrust("785.197.193.203:3884", 72.2)
        // require.NoError(t, err)
        // err = node1.SetTrust("232.132.61.226:4", 2.887)
        // require.NoError(t, err)
        // err = node1.SetTrust("5.38.10.20:23", 644.3)
        // require.NoError(t, err)

        // trustResponse1, err := node1.GetTrust(node1.GetAddr())
        // require.NoError(t, err)
        // require.Equal(t, trust1, trustResponse1)

        // trustResponse2, err := node2.GetTrust(node2.GetAddr())
        // require.NoError(t, err)
        // require.Equal(t, trust2, trustResponse2)

        // trustResponse3, err := node3.GetTrust(node3.GetAddr())
        // require.NoError(t, err)
        // require.Equal(t, trust3, trustResponse3)



func Test_DHT_Time_Trusts(t *testing.T) {
	// transp := channel.NewTransport()
	transp := udpFac()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap(), z.WithStartTrust())
	defer nodeB.Stop()

    nodeBAddr := nodeB.GetAddr()

    numNodes := []int{2, 4, 6, 8, 10, 12}
    for _, num := range numNodes {
        var nodeList []z.TestNode
        var IPAddrs []string
        startNodes := time.Now()
        for i := 0; i < num; i++ {
            node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}), z.WithStartTrust())
            nodeList = append(nodeList, node)
            IPAddrs = append(IPAddrs, node.GetAddr())
        }
        startSet := time.Now()
        for i := 0; i < num; i++ {
            err := nodeList[i].SetTrust(IPAddrs[i], float64(i))
            require.NoError(t, err)
        }
        for i := 0; i < num; i++ {
            _, err := nodeList[i].GetTrust(nodeList[i].GetAddr())
            require.NoError(t, err)
            // require.Equal(t, float64(i), tr)
        }
        fmt.Printf("%d nodes: total: %v, set/get: %v\n", num, time.Since(startNodes), time.Since(startSet))
        for _, node := range nodeList {
            node.Stop()
        }
    }
}
