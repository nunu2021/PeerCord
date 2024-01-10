package impl

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/udp"
)

//This is not really a performance test file, the tests are measurements
//They measure the execution time of the key exchange, member addition/removal
//for random networks and DH groups with scaling size (of the group)
//These tests assume the system works (do not check for errors), this is done in the
//integration test with basically is the same but for a fixed group size and done only once
//and merging all 3 perf tests (key exchange, addition and removal)

func randomInt(N int) int {
	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(N)))
	return int(randNum.Int64())
}

func TestCrypto_Perf_DH_Key_Exchange(t *testing.T) {
	//Generate the network
	transp := udp.NewUDP()

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 10)

	for i := 3; i <= 10; i++ {
		//Do the test for group sizes from 3 to 10
		times := make([]time.Duration, 0)
		for try := 0; try < 50; try++ {
			//Do the measurement 50 times
			members := make([]int, 0)
			//Create the DH group
			for j := 0; j < i; j++ {
				k := randomInt(len(peers))
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
						k = randomInt(len(peers))
					}
				}
			}
			//Create the list of receivers (all except the first member of the group)
			receivers := make(map[string]struct{})
			first := true
			for _, v := range members {
				if first {
					first = false
					continue
				}
				receivers[peers[v].GetAddr()] = struct{}{}
			}
			//Measure the DH key exchange execution time
			t := time.Now()
			peers[members[0]].StartDHKeyExchange(receivers)
			times = append(times, time.Since(t))
			time.Sleep(time.Millisecond * 250)
			for _, v := range members {
				peers[v].GroupCallEnd()
			}
		}
		t.Logf("%v: %v,", i, times)
	}
}

func TestCrypto_Perf_DH_Addition(t *testing.T) {
	transp := udp.NewUDP()

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 10)

	for i := 4; i <= 11; i++ {
		times := make([]time.Duration, 0)
		for try := 0; try < 50; try++ {
			members := make([]int, 0)
			for j := 0; j < i; j++ {
				k := randomInt(len(peers))
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
						k = randomInt(len(peers))
					}
				}
			}
			receivers := make(map[string]struct{})
			first := true
			for _, v := range members[:len(members)-1] {
				if first {
					first = false
					continue
				}
				receivers[peers[v].GetAddr()] = struct{}{}
			}
			peers[members[0]].StartDHKeyExchange(receivers)
			t := time.Now()
			peers[members[0]].GroupCallAdd(peers[members[len(members)-1]].GetAddr())
			times = append(times, time.Since(t))
			time.Sleep(time.Millisecond * 250)
			for _, v := range members {
				peers[v].GroupCallEnd()
			}
		}
		t.Logf("%v: %v,", i-1, times)
	}
}

func TestCrypto_Perf_DH_Removal(t *testing.T) {
	transp := udp.NewUDP()

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 10)

	for i := 3; i <= 10; i++ {
		times := make([]time.Duration, 0)
		for try := 0; try < 50; try++ {
			members := make([]int, 0)
			for j := 0; j < i; j++ {
				k := randomInt(len(peers))
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
						k = randomInt(len(peers))
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
			t := time.Now()
			peers[members[0]].GroupCallRemove(peers[members[len(members)-1]].GetAddr())
			times = append(times, time.Since(t))
			time.Sleep(time.Millisecond * 250)
			for _, v := range members {
				peers[v].GroupCallEnd()
			}
		}
		t.Logf("%v: %v,", i, times)
	}
}

func TestCrypto_Perf_DH_Key_Exchange_Network_Size(t *testing.T) {
	transp := udp.NewUDP()

	size := 60

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}
	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 10)

	time.Sleep(time.Second * 2)

	times := make([]time.Duration, 0)
	for try := 0; try < 50; try++ {
		members := make([]int, 0)
		for j := 0; j < 7; j++ {
			k := randomInt(len(peers))
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
					k = randomInt(len(peers))
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
		ti := time.Now()
		peers[members[0]].StartDHKeyExchange(receivers)
		times = append(times, time.Since(ti))
		time.Sleep(time.Millisecond * 250)
		for _, v := range members {
			peers[v].GroupCallEnd()
		}
	}
	t.Logf("%v: %v,", size, times)
}

func TestCrypto_Perf_DH_Addition_Network_Size(t *testing.T) {
	transp := udp.NewUDP()

	size := 60

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 10)

	times := make([]time.Duration, 0)
	for try := 0; try < 50; try++ {
		members := make([]int, 0)
		for j := 0; j < 7; j++ {
			k := randomInt(len(peers))
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
					k = randomInt(len(peers))
				}
			}
		}
		receivers := make(map[string]struct{})
		first := true
		for _, v := range members[:len(members)-1] {
			if first {
				first = false
				continue
			}
			receivers[peers[v].GetAddr()] = struct{}{}
		}
		peers[members[0]].StartDHKeyExchange(receivers)
		t := time.Now()
		peers[members[0]].GroupCallAdd(peers[members[len(members)-1]].GetAddr())
		times = append(times, time.Since(t))
		time.Sleep(time.Millisecond * 250)
		for _, v := range members {
			peers[v].GroupCallEnd()
		}
	}
	t.Logf("%v: %v,", size-1, times)
}

func TestCrypto_Perf_DH_Removal_Network_Size(t *testing.T) {
	transp := udp.NewUDP()

	size := 60

	peers := make([]*z.TestNode, 0)

	for i := 0; i < 30; i++ {
		nodeA := z.NewTestNode(t, NewPeer, transp, "127.0.0.1:0", z.WithHeartbeat(time.Hour),
			z.WithAntiEntropy(time.Second),
			z.WithContinueMongering(0.5), z.WithAutostart(false))
		defer nodeA.Stop()
		peers = append(peers, &nodeA)
	}

	GenerateRandomGraph(peers)

	for _, peer := range peers {
		peer.Start()
	}

	time.Sleep(time.Second * 10)

	times := make([]time.Duration, 0)
	for try := 0; try < 50; try++ {
		members := make([]int, 0)
		for j := 0; j < 7; j++ {
			k := randomInt(len(peers))
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
					k = randomInt(len(peers))
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
		t := time.Now()
		peers[members[0]].GroupCallRemove(peers[members[len(members)-1]].GetAddr())
		times = append(times, time.Since(t))
		time.Sleep(time.Millisecond * 250)
		for _, v := range members {
			peers[v].GroupCallEnd()
		}
	}
	t.Logf("%v: %v,", size, times)
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
