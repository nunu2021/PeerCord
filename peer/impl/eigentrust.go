package impl

// TODO DONE: remove syntax errors from eigen code
// TODO DONE: figure out a way to have a map of maps
// TODO DONE: Implement exec message functions
// TODO DONE: implement waiting for all trust values
// TODO DONE: implement the rest of the algorithm
// TODO DONE: Check if I implemented the t1c1i calculations correctly
// TODO: Fix Linting Errors
// TODO: Add tests

import (
	"math"
	"time"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type EigenTrust struct {
	// total number of calls completed with peer with ip address (string)
	IncomingCallRatingSum safeMap[string, int]

	// peers that this peer has called
	CallsOutgoingTo safeMap[string, int]

	// peers that have called this peer
	CallsIncomingFrom safeMap[string, int]

	// global Trust value initial set to p.
	// this maps from k -> trust value
	GlobalTrustValue float64

	// step of global trust value computation
	// is reset to 0 once global trust value computation complete
	k uint

	// a priori notion of trust
	p float64

	// tells whether the peer is currenly in the middle of computing its trust value
	ComputingTrustValue bool

	// a map of the received trust values from CallsOutgoingTo peers
	// the map is mapped with the corresponding k-value
	ReceivedTrustValues safeMap[string, float64]

	// keeps track of the which peer we have received a trust value from
	// per Eigen Iteration

	TrustReceivedFrom safeMap[string, int]
}

func NewEigenTrust(totalPeers uint) EigenTrust {
	return EigenTrust{
		IncomingCallRatingSum: newSafeMap[string, int](),
		CallsOutgoingTo:       newSafeMap[string, int](),
		CallsIncomingFrom:     newSafeMap[string, int](),
		GlobalTrustValue:      0.0,
		k:                     0,
		p:                     1 / float64(totalPeers),
		ComputingTrustValue:   false,
		ReceivedTrustValues:   newSafeMap[string, float64](),
		TrustReceivedFrom:     newSafeMap[string, int](),
	}
}

// function invoked after call ends to update peer rating in eigentrust table
func (n *node) EigenRatePeer(peerIp string, ratingPerCall int) {
	c, ok := n.eigenTrust.IncomingCallRatingSum.get(peerIp)
	if ok {
		n.eigenTrust.IncomingCallRatingSum.set(peerIp, c+ratingPerCall)
	} else {
		n.eigenTrust.IncomingCallRatingSum.set(peerIp, ratingPerCall)
	}

}

// Computes the Global Trust Value for peer
func (n *node) ComputeGlobalTrustValue() error {
	n.eigenTrust.ComputingTrustValue = true

	// request t0 from all CallsOutgoingTo peers
	for peer, _ := range n.eigenTrust.CallsOutgoingTo.data {
		err := n.SendTrustValueRequest(true, peer)
		if err != nil {
			return err
		}
	}

	delta := float64(10000)
	counter := uint(0)
	for {
		if delta < n.conf.EigenEpsilon || counter > n.conf.EigenCalcIterations {
			// trust computation complete
			n.eigenTrust.ComputingTrustValue = false
			return nil
		}

		// wait till we get all trust responses
		n.WaitForEigenTrusts()

		// calculate t+1 and store
		t_1 := float64(0)

		for _, trust := range n.eigenTrust.CallsOutgoingTo.data {
			t_1 += float64(trust)
		}

		t_1 *= (1 - n.conf.EigenAValue)
		t_1 += n.conf.EigenAValue * (1 / n.eigenTrust.p)

		// send its local trust value to all CallsIncomingFrom
		internalMap := n.eigenTrust.CallsIncomingFrom.internalMap()
		defer n.eigenTrust.CallsIncomingFrom.unlock()
		for peer, _ := range internalMap {
			n.SendTrustValueResponse(peer, true)
		}

		// update delta
		delta = math.Abs(n.eigenTrust.GlobalTrustValue - t_1)

		// update Global trust value
		n.eigenTrust.k++
		n.eigenTrust.GlobalTrustValue = t_1

	}

}

func (n *node) SetTimer(dur time.Duration, timerChan chan bool) {
	time.Sleep(dur)
	timerChan <- true
}

// TODO
// wait some time and then check if we got all the responses
// if by the end of the timer, we haven't, send requests to the peer that haven't sent
func (n *node) WaitForEigenTrusts() error {
	// set first timer
	timerChan := make(chan bool)
	go n.SetTimer(time.Duration(n.conf.EigenPulseWait/4), timerChan)
	for {
		select {
		case <-timerChan:
			// check dict
			missing := n.CheckReceivedTrustValueCount()

			// if not full, request the missing ones
			if len(missing) > 0 {
				for peer, _ := range missing {
					err := n.SendTrustValueRequest(true, peer)
					if err != nil {
						return err
					}
				}
				go n.SetTimer(time.Duration(n.conf.EigenPulseWait/4), timerChan)
			} else {
				return nil
			}

		default:
			// check dict
			missing := n.CheckReceivedTrustValueCount()
			// if finished, then
			if len(missing) == 0 {
				return nil
			}
		}

	}
}

func (n *node) CheckReceivedTrustValueCount() map[string]int {
	internalMap := n.eigenTrust.CallsOutgoingTo.internalMap()
	defer n.eigenTrust.CallsOutgoingTo.unlock()

	missing := make(map[string]int)

	for peer := range internalMap {
		_, ok := n.eigenTrust.ReceivedTrustValues.get(peer)
		if !ok {
			missing[peer] = 1
		}
	}

	return missing
}

// processes packet that is requesting this peer's trust value
func (n *node) SendTrustValueRequest(includeLocalTrust bool, dest string) error {
	eigenReqMsg := types.EigenTrustRequestMessage{
		KStep:        n.eigenTrust.k,
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

func (n *node) SendTrustValueResponse(source string, includeLocal bool) error {
	trust := n.eigenTrust.GlobalTrustValue
	if includeLocal {

		internalMap := n.eigenTrust.IncomingCallRatingSum.internalMap()
		defer n.eigenTrust.CallsIncomingFrom.unlock()

		count := 0

		for _, val := range internalMap {
			count += max(val, 0)
		}

		rating, ok := n.eigenTrust.IncomingCallRatingSum.get(source)
		if !ok || rating < 0 {
			rating = 0
		}

		localTrustValue := float64(0)
		if count != 0 {
			localTrustValue = float64(rating) / float64(count)
		}

		trust *= localTrustValue
	}
	eigenResponseMsg := types.EigenTrustResponseMessage{
		KStep:  n.eigenTrust.k,
		Source: n.conf.Socket.GetAddress(),
		Value:  trust,
	}
	return n.marshalAndUnicast(source, eigenResponseMsg)
}

func (n *node) ExecEigenTrustRequestMessage(Msg types.Message, pkt transport.Packet) error {
	eigenRqstMsg, ok := Msg.(*types.EigenTrustRequestMessage)
	if !ok {
		panic("not a data reply message")
	}

	return n.SendTrustValueResponse(eigenRqstMsg.Source, true)
}

// Upon receiving a reponse from peer with peer's trust value for itself
func (n *node) ExecEigenTrustResponseMessage(Msg types.Message, pkt transport.Packet) error {

	eigenRspnMsg, ok := Msg.(*types.EigenTrustResponseMessage)
	if !ok {
		panic("not a data reply message")
	}
	n.eigenTrust.ReceivedTrustValues.set(eigenRspnMsg.Source, eigenRspnMsg.Value)

	return nil
}
