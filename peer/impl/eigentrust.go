package impl

// TOD DONE: remove syntax errors from eigen code
// TOD DONE: figure out a way to have a map of maps
// TOD DONE: Implement exec message functions
// TOD DONE: implement waiting for all trust values
// TOD DONE: implement the rest of the algorithm
// TOD DONE: Check if I implemented the t1c1i calculations correctly
// TOD DONE: figure out a way to get total number of peers in a system
// TOD DONE: Fix Linting Errors
// TOD DONE: Add tests

import (
	"fmt"
	"math"
	"sync"
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

	// step of global trust value computation
	// is reset to 0 once global trust value computation complete
	k uint

	// a priori notion of trust
	p float64

	// tells whether the peer is currenly in the middle of computing its trust value
	ComputingTrustValue      bool
	ComputingTrustValueMutex sync.Mutex

	// a map of the received trust values from CallsOutgoingTo peers
	// the map is mapped with the corresponding k-value
	ReceivedTrustValues safeMap[string, float64]

	// keeps track of the which peer we have received a trust value from
	// per Eigen Iteration

	TrustReceivedFrom safeMap[string, int]

	// global trust value of this peer stored locally
	// this is implemented for se cure eigentrust only
	GlobalTrustValue float64
}

func NewEigenTrust(totalPeers uint) EigenTrust {
	tempP := 1 / float64(totalPeers)
	fmt.Println(tempP, totalPeers)
	return EigenTrust{
		IncomingCallRatingSum: newSafeMap[string, int](),
		CallsOutgoingTo:       newSafeMap[string, int](),
		CallsIncomingFrom:     newSafeMap[string, int](),
		k:                     0,
		p:                     tempP,
		ComputingTrustValue:   false,
		ReceivedTrustValues:   newSafeMap[string, float64](),
		TrustReceivedFrom:     newSafeMap[string, int](),
		GlobalTrustValue:      tempP,
	}
}

// function invoked after call ends to update peer rating in eigentrust table
func (n *node) EigenRatePeer(peerIP string, ratingPerCall int) {
	c, ok := n.eigenTrust.IncomingCallRatingSum.get(peerIP)
	if ok {
		n.eigenTrust.IncomingCallRatingSum.set(peerIP, c+ratingPerCall)
	} else {
		n.eigenTrust.IncomingCallRatingSum.set(peerIP, ratingPerCall)
	}

	n.eigenTrust.CallsIncomingFrom.set(peerIP, 1)

}

func (n *node) SetEigenState(value bool) {
	n.eigenTrust.ComputingTrustValueMutex.Lock()
	n.eigenTrust.ComputingTrustValue = true
	n.eigenTrust.ComputingTrustValueMutex.Unlock()
}

// Computes the Global Trust Value for peer
func (n *node) ComputeGlobalTrustValue() (float64, error) {
	globalTrustVal := n.eigenTrust.GlobalTrustValue

	// globalTrustVal, err := n.GetTrust(n.GetAddress())
	// if err != nil {
	// 	return 0, err
	// }

	n.SetEigenState(true)

	// request t0 from all CallsOutgoingTo peers
	for peer := range n.eigenTrust.CallsOutgoingTo.data {
		err := n.SendTrustValueRequest(true, peer)
		if err != nil {
			n.SetEigenState(false)
			return 0, err
		}
	}

	delta := float64(10000)
	counter := uint(0)
	tPlus := float64(0)
	for {
		if delta < n.conf.EigenEpsilon || counter > n.conf.EigenCalcIterations {
			// trust computation complete

			break
		}

		// wait till we get all trust responses
		err := n.WaitForEigenTrusts()
		if err != nil {
			n.SetEigenState(false)
			return 0, err
		}

		// calculate t+1 and store
		tPlus = float64(0)

		internalMapR := n.eigenTrust.ReceivedTrustValues.internalMap()
		for _, trust := range internalMapR {
			tPlus += float64(trust)
		}
		n.eigenTrust.ReceivedTrustValues.unlock()

		tPlus *= (1 - n.conf.EigenAValue)
		tPlus += n.conf.EigenAValue * (n.eigenTrust.p)

		// send its local trust value to all CallsIncomingFrom
		internalMap := n.eigenTrust.CallsIncomingFrom.internalMap()

		for peer := range internalMap {

			err := n.SendTrustValueResponse(peer, true)
			if err != nil {
				n.SetEigenState(false)
				return 0, err
			}
		}

		n.eigenTrust.CallsIncomingFrom.unlock()

		// update delta
		delta = math.Abs(globalTrustVal - tPlus)

		// update Global trust value
		n.eigenTrust.k++

		// err = n.SetTrust(n.GetAddress(), tPlus)
		// if err != nil {
		// 	n.SetEigenState(false)
		// 	return 0, err
		// }

		n.eigenTrust.GlobalTrustValue = tPlus
		globalTrustVal = tPlus
		counter++

	}

	n.SetEigenState(false)
	fmt.Println("being called in", n.GetAddress(), "value: ", n.eigenTrust.GlobalTrustValue)

	return tPlus, nil

}

func (n *node) SetTimer(dur time.Duration, timerChan chan bool) {
	time.Sleep(dur)
	timerChan <- true
}

// wait some time and then check if we got all the responses
// if by the end of the timer, we haven't, send requests to the peer that haven't sent
func (n *node) WaitForEigenTrusts() error {
	// set first timer
	timerChan := make(chan bool)
	go n.SetTimer(time.Duration(n.conf.EigenPulseWait/6), timerChan)
	for {
		select {
		case <-timerChan:

			// check dict
			missing := n.CheckReceivedTrustValueCount()

			// if not full, request the missing ones
			if len(missing) > 0 {
				for peer := range missing {

					err := n.SendTrustValueRequest(true, peer)
					if err != nil {
						return err
					}
				}
				go n.SetTimer(time.Duration(n.conf.EigenPulseWait/6), timerChan)
			} else {
				return nil
			}

		default:
			// check dict
			missing := n.CheckReceivedTrustValueCount()
			// if finished, then
			if len(missing) == 0 {
				go n.finishTimer(timerChan)
				return nil

			}
		}

	}
}

func (n *node) finishTimer(timerChan chan bool) {
	for {
		<-timerChan
		return
	}
}

func (n *node) CheckReceivedTrustValueCount() map[string]int {
	internalMap := n.eigenTrust.CallsOutgoingTo.internalMap()

	missing := make(map[string]int)

	for peer := range internalMap {
		_, ok := n.eigenTrust.ReceivedTrustValues.get(peer)
		if !ok {
			missing[peer] = 1
		}
	}

	n.eigenTrust.CallsOutgoingTo.unlock()

	return missing
}

// processes packet that is requesting this peer's trust value
func (n *node) SendTrustValueRequest(includeLocalTrust bool, dest string) error {
	eigenReqMsg := types.EigenTrustRequestMessage{
		KStep:        n.eigenTrust.k,
		Source:       n.conf.Socket.GetAddress(),
		IncludeLocal: includeLocalTrust,
	}
	err := n.marshalAndUnicast(dest, eigenReqMsg)
	return err
}

func (n *node) SendTrustValueResponse(source string, includeLocal bool) error {
	trust := n.eigenTrust.GlobalTrustValue
	// trust, err := n.GetTrust(n.GetAddress())
	// if err != nil {
	// 	return err
	// }

	if includeLocal {

		internalMap := n.eigenTrust.IncomingCallRatingSum.internalMap()

		count := 0

		for _, val := range internalMap {

			count += max(val, 0)
		}
		n.eigenTrust.IncomingCallRatingSum.unlock()

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
	err := n.marshalAndUnicast(source, eigenResponseMsg)
	return err
}

func (n *node) ExecEigenTrustRequestMessage(Msg types.Message, pkt transport.Packet) error {
	fmt.Println("executing eigen request message at", n.GetAddress())

	// if this node is not already calculating its trust value, then start calculating trust values
	eigenRqstMsg, ok := Msg.(*types.EigenTrustRequestMessage)
	if !ok {
		panic("not a data reply message")
	}

	// if not already in an eigen computing state, switch over (this will enable a system wide pulse!)
	n.eigenTrust.ComputingTrustValueMutex.Lock()
	if !n.eigenTrust.ComputingTrustValue {
		n.eigenTrust.ComputingTrustValue = true
		go n.ComputeGlobalTrustValue()

	}
	n.eigenTrust.ComputingTrustValueMutex.Unlock()

	err := n.SendTrustValueResponse(eigenRqstMsg.Source, true)

	return err
}

// Upon receiving a reponse from peer with peer's trust value for itself
func (n *node) ExecEigenTrustResponseMessage(Msg types.Message, pkt transport.Packet) error {
	fmt.Println("executing eigen response message at", n.GetAddress())

	eigenRspnMsg, ok := Msg.(*types.EigenTrustResponseMessage)
	if !ok {
		panic("not a data reply message")
	}

	n.eigenTrust.ReceivedTrustValues.set(eigenRspnMsg.Source, eigenRspnMsg.Value)
	return nil
}

/**
Testing Functions
Helper functions to use in testing
**/

func (n *node) AddToCallsOutgoingTo(peer string) {
	n.eigenTrust.CallsOutgoingTo.set(peer, 1)
}

func (n *node) AddToCallsIncomingFrom(peer string) {
	n.eigenTrust.CallsIncomingFrom.set(peer, 1)
}
