package integration

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
	"testing"
	"time"
)

func Test_Multicast(t *testing.T) {
	transp := channel.NewTransport()

	// Define the graph
	type Edge struct {
		x, y int
	}
	nbNodes := 5
	edges := []Edge{
		Edge{x: 0, y: 1},
		Edge{x: 0, y: 3},
		Edge{x: 3, y: 4},
	}

	// Create the nodes
	nodes := make([]z.TestNode, nbNodes)
	for i := 0; i < nbNodes; i++ {
		nodes[i] = z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0")
		defer nodes[i].Stop()
	}

	// Add the edges
	for _, e := range edges {
		nodes[e.x].AddPeer(nodes[e.y].GetAddr())
		nodes[e.y].AddPeer(nodes[e.x].GetAddr())
	}

	// Fill the routing tables
	for _, n := range nodes {
		emptyMsg := types.EmptyMessage{}
		data, err := json.Marshal(&emptyMsg)
		require.NoError(t, err)

		msg := transport.Message{
			Type:    emptyMsg.Name(),
			Payload: data,
		}
		require.NoError(t, n.Broadcast(msg))
	}

	time.Sleep(time.Second)

	// TODO Multicast

}
