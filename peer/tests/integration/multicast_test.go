package integration

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
	"math/rand"
	"testing"
	"time"
)

func Test_Multicast(t *testing.T) {
	transp := channel.NewTransport()
	rng := rand.New(rand.NewSource(42))

	// Define the simulation parameters
	nbSteps := 100

	// Define the graph
	type Edge struct {
		x, y int
	}
	const nbNodes int = 6
	edges := []Edge{
		Edge{x: 0, y: 1},
		Edge{x: 1, y: 2},
		Edge{x: 2, y: 0},
		Edge{x: 2, y: 3},
		Edge{x: 3, y: 4},
		Edge{x: 3, y: 5},
	}

	// Create the nodes
	nodes := make([]z.TestNode, nbNodes)
	var isInGroup [nbNodes][nbNodes]bool
	var nbMessagesReceivedExpected [nbNodes]int
	var multicastGroups [nbNodes]string

	for i := 0; i < nbNodes; i++ {
		// Only the first heartbeat is needed
		nodes[i] = z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0",
			z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5),
		)
		defer nodes[i].Stop()

		multicastGroups[i] = nodes[i].NewMulticastGroup()
	}

	// Add the edges
	for _, e := range edges {
		nodes[e.x].AddPeer(nodes[e.y].GetAddr())
		nodes[e.y].AddPeer(nodes[e.x].GetAddr())
	}

	time.Sleep(3 * time.Second)

	// Perform several steps of multicast
	for step := 0; step < nbSteps; step++ {
		// Update the multicast groups
		for i := 0; i < nbNodes; i++ {
			for j := 0; j < nbNodes; j++ {
				if rng.Float32() < 0.2 {
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

		time.Sleep(100 * time.Millisecond)

		// Each peer sends a message to its multicast group
		for i := 0; i < nbNodes; i++ {
			chat := types.ChatMessage{Message: "chat message"}
			data, err := json.Marshal(&chat)
			require.NoError(t, err)

			msg := transport.Message{
				Type:    chat.Name(),
				Payload: data,
			}
			require.NoError(t, nodes[i].Multicast(msg, multicastGroups[i]))

			for j := 0; j < nbNodes; j++ {
				if isInGroup[i][j] {
					nbMessagesReceivedExpected[j]++
				}
			}

			// Wait for the messages to propagate through the network
			time.Sleep(100 * time.Millisecond)

			// Check that each peer has received the right number of messages
			for j := 0; j < nbNodes; j++ {
				require.Equal(t, nbMessagesReceivedExpected[j], len(nodes[j].GetChatMsgs()))
			}
		}
	}
}
