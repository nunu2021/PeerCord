package unit

import (
	// "encoding/json"
	"fmt"
	// "io"
	// "math/rand"
	// "sort"
	// "sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	// "go.dedis.ch/cs438/internal/graph"
	z "go.dedis.ch/cs438/internal/testing"
	// "go.dedis.ch/cs438/peer"
	// "go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
)

func Test_DHT_Bootstrap_Empty(t *testing.T) {
	transp := channel.NewTransport()

    node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer node1.Stop()

    require.Equal(t, true, node1.GetBootstrap())
    require.Len(t, node1.GetNodeList(), 0)
}



func Test_DHT_Bootstrap_Single(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer node1.Stop()

    require.Equal(t, true, node1.GetBootstrap())
    node1.AddNodeBootstrap("127.0.0.1:1")

    require.Len(t, node1.GetNodeList(), 1)
}



func Test_DHT_Bootstrap_Many(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer node1.Stop()

    require.Equal(t, true, node1.GetBootstrap())

	node1.AddNodeBootstrap("127.0.0.1:1")
	node1.AddNodeBootstrap("127.0.0.1:2")
	node1.AddNodeBootstrap("127.0.0.1:3")
	node1.AddNodeBootstrap("127.0.0.1:4")
	node1.AddNodeBootstrap("127.0.0.1:5")
	node1.AddNodeBootstrap("127.0.0.1:6")
	node1.AddNodeBootstrap("127.0.0.1:7")
	node1.AddNodeBootstrap("127.0.0.1:8")
	node1.AddNodeBootstrap("127.0.0.1:9")
	node1.AddNodeBootstrap("127.0.0.1:10")
	node1.AddNodeBootstrap("127.0.0.1:11")

    require.Len(t, node1.GetNodeList(), node1.GetNodeLimit())
}



func Test_DHT_No_Bootstrap(t *testing.T) {
	transp := channel.NewTransport()

    node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

    require.Equal(t, false, node1.GetBootstrap())
    require.Len(t, node1.GetNodeList(), 0)

	node1.AddNodeBootstrap("127.0.0.1:1")
    require.Len(t, node1.GetNodeList(), 0)
}


func Test_DHT_Hash(t *testing.T) {
	transp := channel.NewTransport()

    node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

    p := node1.Hash("0.0.0.0:0")
    pSol := types.Point([]uint16{0, 0, 0})
    require.Equal(t, pSol, p)

    p = node1.Hash("10.5.2.100:567")
    pSol = types.Point([]uint16{2660, 1282, 567})
    require.Equal(t, pSol, p)
}

func Test_DHT_Overlap1D(t *testing.T) {
	transp := channel.NewTransport()

    node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

    require.Equal(t, false, node1.Overlap1D(0, 10, 14, 19))
    require.Equal(t, false, node1.Overlap1D(0, 10, 12, 19))
    require.Equal(t, true, node1.Overlap1D(0, 10, 11, 19))
    require.Equal(t, true, node1.Overlap1D(0, 10, 4, 19))
    require.Equal(t, true, node1.Overlap1D(0, 10, 4, 9))
    require.Equal(t, true, node1.Overlap1D(10, 15, 4, 9))
    require.Equal(t, false, node1.Overlap1D(10, 15, 4, 8))
}


func Test_DHT_BordersZone(t *testing.T) {
	transp := channel.NewTransport()

    node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

    zone1 := types.Zone{
        LowerLeft: types.Point([]uint16{0, 0, 0}),
        UpperRight: types.Point([]uint16{10, 10, 10}),
    }
    zone2 := types.Zone{
        LowerLeft: types.Point([]uint16{11, 0, 0}),
        UpperRight: types.Point([]uint16{20, 11, 11}),
    }
    zone3 := types.Zone{
        LowerLeft: types.Point([]uint16{15, 11, 11}),
        UpperRight: types.Point([]uint16{16, 12, 12}),
    }
    zone4 := types.Zone{
        LowerLeft: types.Point([]uint16{45, 14, 45}),
        UpperRight: types.Point([]uint16{66, 19, 56}),
    }

    require.Equal(t, true, node1.BordersZone(zone1, zone2))
    require.Equal(t, true, node1.BordersZone(zone2, zone3))
    require.Equal(t, false, node1.BordersZone(zone1, zone3))
    require.Equal(t, false, node1.BordersZone(zone1, zone4))
    require.Equal(t, false, node1.BordersZone(zone2, zone4))
    require.Equal(t, false, node1.BordersZone(zone3, zone4))
}

func Test_DHT_Query_Bootstrap_Simple(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer node1.Stop()

    node1Addr := node1.GetAddr()

    node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node2.Stop()

	node2.AddPeer(node1.GetAddr())

    require.Len(t, node2.GetRoutingTable(), 2)

    err := node2.JoinDHT()

    require.NoError(t, err)
    require.Len(t, node1.GetRoutingTable(), 2)

    zone := types.Zone{
        LowerLeft: types.Point([]uint16{0, 0, 0}),
        UpperRight: types.Point([]uint16{0xFFFF, 0xFFFF, 0xFFFF}),
    }
    require.Equal(t, zone, node2.ReturnDHTArea())

    require.Len(t, node2.ReturnDHTNeighbors(), 0)
    require.Len(t, node2.ReturnDHTPoints(), 0)

    bNodes := node1.ReturnBootstrapNodes()
    require.Len(t, bNodes, 1)
    require.Equal(t, node2.GetAddr(), bNodes[0])
}


func Test_DHT_Query_Bootstrap_Many(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer node1.Stop()

    fmt.Printf("Bootstrap node address: node 1 - %s\n", node1.GetAddr())

    node1Addr := node1.GetAddr()

    node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node2.Stop()
    node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node3.Stop()
    node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node4.Stop()
    fmt.Printf("Other node address: node 2 - %s, node 3 - %s, node 4 - %s\n", node2.GetAddr(), node3.GetAddr(), node4.GetAddr())

	node2.AddPeer(node1.GetAddr())
	node3.AddPeer(node1.GetAddr())
	node4.AddPeer(node1.GetAddr())

    require.Len(t, node2.GetRoutingTable(), 2)
    require.Len(t, node3.GetRoutingTable(), 2)
    require.Len(t, node4.GetRoutingTable(), 2)

    err := node2.JoinDHT()
    require.NoError(t, err)

    err = node3.JoinDHT()
    require.NoError(t, err)

    err = node4.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second)
    require.Len(t, node1.GetRoutingTable(), 4)

    bNodes := node1.ReturnBootstrapNodes()
    fmt.Println(bNodes)
    require.Len(t, bNodes, 3)
    require.Equal(t, node2.GetAddr(), bNodes[0])
    require.Equal(t, node3.GetAddr(), bNodes[1])
    require.Equal(t, node4.GetAddr(), bNodes[2])
}


func Test_DHT_Zone_Division_5_Nodes_With_Sleep(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer node1.Stop()

    fmt.Printf("Bootstrap node address: node 1 - %s\n", node1.GetAddr())

    node1Addr := node1.GetAddr()

    node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node2.Stop()
    node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node3.Stop()
    node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node4.Stop()
    node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node5.Stop()
    node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{node1Addr}))
	defer node6.Stop()

	node2.AddPeer(node1.GetAddr())
	node3.AddPeer(node1.GetAddr())
	node4.AddPeer(node1.GetAddr())
	node5.AddPeer(node1.GetAddr())
	node6.AddPeer(node1.GetAddr())

    err := node2.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second * 3)

    err = node3.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second * 3)

    err = node4.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second * 3)

    err = node5.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second * 3)

    err = node6.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second * 3)

    node2Area := node2.ReturnDHTArea()
    node3Area := node3.ReturnDHTArea()
    node4Area := node4.ReturnDHTArea()
    node5Area := node5.ReturnDHTArea()
    node6Area := node6.ReturnDHTArea()

    node2Neighbors := node2.NeighborsToString()
    node3Neighbors := node3.NeighborsToString()
    node4Neighbors := node4.NeighborsToString()
    node5Neighbors := node5.NeighborsToString()
    node6Neighbors := node6.NeighborsToString()

    fmt.Printf("Node 2 --\nArea: %s\n%s\n", node2Area.String(), node2Neighbors)
    fmt.Printf("Node 3 --\nArea: %s\n%s\n", node3Area.String(), node3Neighbors)
    fmt.Printf("Node 4 --\nArea: %s\n%s\n", node4Area.String(), node4Neighbors)
    fmt.Printf("Node 5 --\nArea: %s\n%s\n", node5Area.String(), node5Neighbors)
    fmt.Printf("Node 6 --\nArea: %s\n%s\n", node6Area.String(), node6Neighbors)

    // zone2 := types.Zone{
    //     LowerLeft: types.Point([]uint16{0, 0, 0}),
    //     UpperRight: types.Point([]uint16{0x7FFF, 0xFFFF, 0xFFFF}),
    // }
    // zone3 := types.Zone{
    //     LowerLeft: types.Point([]uint16{0x8000, 0, 0}),
    //     UpperRight: types.Point([]uint16{0xFFFF, 0xFFFF, 0xFFFF}),
    // }
    // require.Equal(t, zone2, node2Area)
    // require.Equal(t, zone3, node3Area)

    // node2Neighbors := node2.ReturnDHTNeighbors()
    // require.Len(t, node2Neighbors, 1)
    // require.Equal(t, node3Area, node2Neighbors[node3.GetAddr()])

    // node3Neighbors := node3.ReturnDHTNeighbors()
    // require.Len(t, node3Neighbors, 1)
    // require.Equal(t, node2Area, node3Neighbors[node2.GetAddr()])
}


func Test_DHT_Zone_Division_6_Nodes(t *testing.T) {
	transp := channel.NewTransport()

	nodeB := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrap())
	defer nodeB.Stop()

    fmt.Printf("Bootstrap node address: %s\n", nodeB.GetAddr())

    nodeBAddr := nodeB.GetAddr()

    node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
	defer node1.Stop()
    node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
	defer node2.Stop()
    node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
	defer node3.Stop()
    node4 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
	defer node4.Stop()
    node5 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
	defer node5.Stop()
    node6 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithBootstrapAddrs([]string{nodeBAddr}))
	defer node6.Stop()

	node1.AddPeer(nodeB.GetAddr())
	node2.AddPeer(nodeB.GetAddr())
	node3.AddPeer(nodeB.GetAddr())
	node4.AddPeer(nodeB.GetAddr())
	node5.AddPeer(nodeB.GetAddr())
	node6.AddPeer(nodeB.GetAddr())

    err := node1.JoinDHT()
    require.NoError(t, err)

    err = node2.JoinDHT()
    require.NoError(t, err)

    err = node3.JoinDHT()
    require.NoError(t, err)

    err = node4.JoinDHT()
    require.NoError(t, err)

    err = node5.JoinDHT()
    require.NoError(t, err)

    err = node6.JoinDHT()
    require.NoError(t, err)

    time.Sleep(time.Second * 3)

    node1Area := node1.ReturnDHTArea()
    node2Area := node2.ReturnDHTArea()
    node3Area := node3.ReturnDHTArea()
    node4Area := node4.ReturnDHTArea()
    node5Area := node5.ReturnDHTArea()
    node6Area := node6.ReturnDHTArea()

    node1Neighbors := node1.NeighborsToString()
    node2Neighbors := node2.NeighborsToString()
    node3Neighbors := node3.NeighborsToString()
    node4Neighbors := node4.NeighborsToString()
    node5Neighbors := node5.NeighborsToString()
    node6Neighbors := node6.NeighborsToString()

    fmt.Printf("Node 2 --\nArea: %s\n%s\n", node1Area.String(), node1Neighbors)
    fmt.Printf("Node 3 --\nArea: %s\n%s\n", node2Area.String(), node2Neighbors)
    fmt.Printf("Node 4 --\nArea: %s\n%s\n", node3Area.String(), node3Neighbors)
    fmt.Printf("Node 5 --\nArea: %s\n%s\n", node4Area.String(), node4Neighbors)
    fmt.Printf("Node 6 --\nArea: %s\n%s\n", node5Area.String(), node5Neighbors)
    fmt.Printf("Node 7 --\nArea: %s\n%s\n", node6Area.String(), node6Neighbors)

}

