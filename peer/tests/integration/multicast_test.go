package integration

import (
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport/channel"
	"math/rand"
	"testing"
	"time"
)

func Test_Multicast(t *testing.T) {
	transp := channel.NewTransport()
	rng := rand.New(rand.NewSource(42))

	// Define the simulation parameters
	nbSteps := 3 // TODO more

	// Define the graph
	type Edge struct {
		x, y int
	}
	const nbNodes int = 5
	edges := []Edge{
		Edge{x: 0, y: 1},
		Edge{x: 0, y: 3},
		Edge{x: 3, y: 4},
	}

	// Create the nodes
	nodes := make([]z.TestNode, nbNodes)
	var isInGroup [nbNodes][nbNodes]bool
	var multicastGroups [nbNodes]string

	for i := 0; i < nbNodes; i++ {
		// Only the first heartbeat is needed
		nodes[i] = z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour), z.WithAntiEntropy(100*time.Millisecond))
	}

	// Add the edges
	for _, e := range edges {
		nodes[e.x].AddPeer(nodes[e.y].GetAddr())
		nodes[e.y].AddPeer(nodes[e.x].GetAddr())
	}

	// Start the nodes
	for i := 0; i < nbNodes; i++ {
		require.NoError(t, nodes[i].Start())
		defer require.NoError(t, nodes[i].Stop())

		multicastGroups[i] = nodes[i].NewMulticastGroup()
	}
	time.Sleep(time.Second)

	// Perform several steps of multicast
	for step := 0; step < nbSteps; step++ {
		// Update the multicast groups
		for i := 0; i < nbNodes; i++ {
			for j := 0; j < nbNodes; j++ {
				if i != j && rng.Float32() < 0.2 {
					if isInGroup[i][j] {
						require.NoError(t, nodes[j].LeaveMulticastGroup(nodes[i].GetAddr(), multicastGroups[i]))
						isInGroup[i][j] = false
					} else {
						require.NoError(t, nodes[j].JoinMulticastGroup(nodes[i].GetAddr(), multicastGroups[i]))
						isInGroup[i][j] = true
					}
				}
			}
		}

		// Each peer sends a message to its multicast group
		for i := 0; i < nbNodes; i++ {
			//nodes[i].Multicast()
		}

		time.Sleep(100 * time.Millisecond)
	}
}
