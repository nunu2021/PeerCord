package integration

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport/udp"
)

func randInt(N int) int {
	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(N)))
	return int(randNum.Int64())
}

// Scenario with 50 nodes in network, 10 initially in group call
// Then 5 are added and 5 removed (random order) every 3 seconds
func TestCrypto_Int_DH_Key_Exchange(t *testing.T) {
	transp := udp.NewUDP()

	groupSize := 5

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 5)

	members := make([]int, 0)
	//Initial group
	for j := 0; j < groupSize; j++ {
		k := randInt(len(peers))
		found := false
		for !found {
			contained := false
			for _, v := range members {
				if v == k {
					contained = true
					break
				}
			}
			if !contained {
				found = true
				members = append(members, k)
			} else {
				k = randInt(len(peers))
			}
		}
	}
	//nodes to add
	additionalMembers := make([]int, 5)
	for j := 0; j < 3; j++ {
		k := randInt(len(peers))
		found := false
		for !found {
			contained := false
			for _, v := range members {
				if v == k {
					contained = true
					break
				}
			}
			for _, v := range additionalMembers {
				if v == k {
					contained = true
					break
				}
			}
			if !contained {
				found = true
				additionalMembers[j] = k
			} else {
				k = randInt(len(peers))
			}
		}
	}
	receivers := make(map[string]struct{})
	first := true
	for _, v := range members {
		if first {
			first = false
			continue
		}
		receivers[peers[v].GetAddr()] = struct{}{}
	}
	peers[members[0]].StartDHKeyExchange(receivers)
	nbRemoval := 0
	nbAdd := 0
	for nbRemoval < 3 || nbAdd < 3 {
		t.Log(nbAdd, nbRemoval)
		time.Sleep(time.Second * 5)
		if nbRemoval == 3 {
			peers[members[0]].GroupCallAdd(peers[additionalMembers[nbAdd]].GetAddr())
			members = append(members, additionalMembers[nbAdd])
			nbAdd++
		} else if nbAdd == 3 || randInt(100) < 50 {
			rdm := randInt(len(members)-1) + 1
			peers[members[0]].GroupCallRemove(peers[members[rdm]].GetAddr())
			members = append(members[:rdm], members[rdm+1:]...)
			nbRemoval++
		} else {
			peers[members[0]].GroupCallAdd(peers[additionalMembers[nbAdd]].GetAddr())
			members = append(members, additionalMembers[nbAdd])
			nbAdd++
		}
	}
	time.Sleep(time.Second * 5)

	for _, v := range members {
		peers[v].GroupCallEnd()
	}
}

// Generate randomly adds peers to nodes. It makes sure the graph is connected
// without orphans.
func GenerateRandomGraph(peers []*z.TestNode) {

	addrToPeer := make(map[string]*z.TestNode)
	for _, peer := range peers {
		addrToPeer[peer.GetAddr()] = peer
	}

	peersNeighboors := make(map[string][]string)

	for i := 1; i < len(peers); i++ {

		connected := false
		for !connected {
			for j := 0; j < i; j++ {
				if mrand.Float64() >= 0.2 {
					continue
				}

				connected = true

				peersNeighboors[peers[j].GetAddr()] = append(peersNeighboors[peers[j].GetAddr()], peers[i].GetAddr())
				peersNeighboors[peers[i].GetAddr()] = append(peersNeighboors[peers[i].GetAddr()], peers[j].GetAddr())
			}
		}
	}

	for k, v := range peersNeighboors {
		addrToPeer[k].AddPeer(v...)
	}
}
