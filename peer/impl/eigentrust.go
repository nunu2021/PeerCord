package impl

// TODO: remove syntax errors from eigen code
// TODO: figure out a way to have a map of maps
// TODO: Implement exec message functions
// TODO: implement waiting for all trust values
// TODO: implement the rest of the algorithm

import (
	"math"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type EigenTrust struct {
	// total number of calls completed with peer with ip address (string)
	IncomingCallCount safeMap[string, int]

	// sum of ratings for all calls completed with peer with ip address (string)
	IncomingCallRatingSum safeMap[string, int]

	// peers that this peer has called
	CallsOutgoingTo safeMap[string, int]

	// peers that have called this peer
	CallsIncomingFrom safeMap[string, int]

	// global Trust value initial set to p
	GlobalTrustValue float64

	// step of global trust value computation
	// is reset to 0 once global trust value computation complete
	k uint

	// a priori notion of trust
	p float64

	// tells whether the peer is currenly in the middle of computing its trust value
	ComputingTrustValue bool

	// map containing a map of the received trust values from CallsOutgoingTo peers
	// the map is mapped with the corresponding k-value
	ReceivedTrustValues safeMap[int, map[string]float64]
}

func NewEigenTrust() EigenTrust {
	return EigenTrust{
		IncomingCallCount:     newSafeMap[string, int](),
		IncomingCallRatingSum: newSafeMap[string, int](),
		CallsOutgoingTo:       newSafeMap[string, int](),
		CallsIncomingFrom:     newSafeMap[string, int](),
		GlobalTrustValue:      0,
		k:                     0,
		p:                     1 / float64(n.conf.TotalPeers),
		ComputingTrustValue:   false,
		ReceivedTrustValues:   newSafeMap[int, map[string]float64], //i cant do this

	}
}

// Called after call ends to update peer rating in eigentrust table
func (n *node) EigenRatePeer(peerIp string, ratingPerCall int) {
	n.eigenTrust.IncomingCallCount[peerIp] += 1
	n.eigenTrust.RatingSum[peerIp] += ratingPerCall
}

// processes packet that is requesting this peer's trust value
func (n *node) ExecEigenRequestTrustMessage() {

}

// Upon receiving a reponse from peer with peer's trust value for itself
func (n *node) ExecEigenResponseTrustMessage() {

}

// Computes the Global Trust Value for peer
func (n *node) ComputeGlobalTrustValue() {
	ComputingTrustValue = true

	// request t0 from all CallsOutgoingTo peers
	for peer, _ := range n.EigenTrust.CallsOutgoingTo.data {
		err := n.SendTrustValueRequest(true, peer)
	}

	delta := 10000

	for {
		if delta < int(n.conf.EigenEpsilon) {
			// trust computation complete
			ComputingTrustValue = false
			return
		}

		// wait till we get all trust responses
		n.WaitForEigenTrusts()

		// calculate t+1 and store
		t_1 := float64(0)

		for _, trust := range n.eigenTrust.CallsOutgoingTo.data {
			t_1 += trust
		}

		t_1 *= (1 - n.conf.EigenAValue)
		t_1 += n.conf.EigenAValue * (1 / n.eigenTrust.p)

		// send its local trust value to all CallsIncomingFrom

		// update delta
		delta = math.Abs(n.eigenTrust.GlobalTrustValue - t_1)

		// update Global trust value
		n.eigenTrust.GlobalTrustValue = t_1

	}

}

// TODO
func (n *node) WaitForEigenTrusts() {
	for {

	}
}

func (n *node) SendTrustValueRequest(includeLocalTrust bool, dest string) error {
	eigenReqMsg := types.EigenTrustRequestMessage{
		kStep:        n.EigenTrust.k,
		Source:       n.conf.Socket.GetAddress(),
		IncludeLocal: includeLocalTrust,
	}

	msg, err := n.conf.MessageRegistry.MarshalMessage(eigenReqMsg)
	if err != nil {
		return err
	}

	err = n.Unicast(dest, msg)
	return err
}

func (n *node) ExecEigenTrustRequestMessage(Msg types.Message, pkt transport.Packet) error {

}

func (n *node) ExecEigenTrustResponseMessage(Msg types.Message, pkt transport.Packet) error {

}
