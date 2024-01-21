package impl

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

	// // global trust value of this peer stored locally
	// // this is implemented for se cure eigentrust only
	// GlobalTrustValue float64

	// // mutual exclusion on the GlobalTrustValue
	// GlobalTrustValueMutex sync.Mutex

	kMutex sync.Mutex
}

func NewEigenTrust(totalPeers uint) EigenTrust {
	tempP := 1.0 / float64(totalPeers)
	if totalPeers > 3 {
		tempP = 0.0
	}
	fmt.Println("is this happenign??", totalPeers)
	return EigenTrust{
		IncomingCallRatingSum: newSafeMap[string, int](),
		CallsOutgoingTo:       newSafeMap[string, int](),
		CallsIncomingFrom:     newSafeMap[string, int](),
		k:                     0,
		p:                     tempP,
		ComputingTrustValue:   false,
		ReceivedTrustValues:   newSafeMap[string, float64](),
		TrustReceivedFrom:     newSafeMap[string, int](),
		// GlobalTrustValue:      tempP,
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
	// n.eigenTrust.GlobalTrustValueMutex.Lock()
	// globalTrustVal := n.eigenTrust.GlobalTrustValue
	// n.eigenTrust.GlobalTrustValueMutex.Unlock()

	globalTrustVal, err := n.GetTrust(n.GetAddress())
	if err != nil {
		return 0, err
	}

	n.SetEigenState(true)

	// request t0 from all CallsOutgoingTo peers
	internalMapCOD := n.eigenTrust.CallsOutgoingTo.internalMap()
	for peer := range internalMapCOD {
		err := n.SendTrustValueRequest(true, peer)
		if err != nil {
			n.SetEigenState(false)
			return 0, err
		}
	}
	n.eigenTrust.CallsOutgoingTo.unlock()

	delta := float64(10000)
	counter := uint(0)
	tPlus := float64(0)
	i := 0
	for {
		i++
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
		n.eigenTrust.kMutex.Lock()
		n.eigenTrust.k++
		n.eigenTrust.kMutex.Unlock()

		err = n.SetTrust(n.GetAddress(), tPlus)
		if err != nil {
			n.SetEigenState(false)
			return 0, err
		}
		// n.eigenTrust.GlobalTrustValueMutex.Lock()
		// n.eigenTrust.GlobalTrustValue = tPlus
		// n.eigenTrust.GlobalTrustValueMutex.Unlock()

		globalTrustVal = tPlus
		counter++

	}

	n.SetEigenState(false)
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
	n.eigenTrust.kMutex.Lock()
	kval := n.eigenTrust.k
	n.eigenTrust.kMutex.Unlock()
	eigenReqMsg := types.EigenTrustRequestMessage{
		KStep:        kval,
		Source:       n.conf.Socket.GetAddress(),
		IncludeLocal: includeLocalTrust,
	}
	err := n.marshalAndUnicast(dest, eigenReqMsg)
	return err
}

func (n *node) SendTrustValueResponse(source string, includeLocal bool) error {

	trust := 1.0

	// trust, err := n.GetTrust(n.GetAddress())

	isP := false
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
		} else {
			isP = true
		}

		trust = localTrustValue

	}
	n.eigenTrust.kMutex.Lock()
	kval := n.eigenTrust.k
	n.eigenTrust.kMutex.Unlock()
	eigenResponseMsg := types.EigenTrustResponseMessage{
		KStep:  kval,
		Source: n.conf.Socket.GetAddress(),
		Value:  trust,
		IsPVal: isP,
	}
	err := n.marshalAndUnicast(source, eigenResponseMsg)
	return err
}

func (n *node) ExecEigenTrustRequestMessage(Msg types.Message, pkt transport.Packet) error {

	// if this node is not already calculating its trust value, then start calculating trust values
	eigenRqstMsg, ok := Msg.(*types.EigenTrustRequestMessage)
	if !ok {
		panic("not a data reply message")
	}

	go n.SendTrustValueResponse(eigenRqstMsg.Source, true)

	// if not already in an eigen computing state, switch over (this will enable a system wide pulse!)
	n.eigenTrust.ComputingTrustValueMutex.Lock()
	if !n.eigenTrust.ComputingTrustValue {
		n.eigenTrust.ComputingTrustValue = true
		go n.ComputeGlobalTrustValue()

	}
	n.eigenTrust.ComputingTrustValueMutex.Unlock()

	return nil
}

// Upon receiving a reponse from peer with peer's trust value for itself
func (n *node) ExecEigenTrustResponseMessage(Msg types.Message, pkt transport.Packet) error {

	eigenRspnMsg, ok := Msg.(*types.EigenTrustResponseMessage)
	if !ok {
		panic("not a data reply message")
	}
	peerTrustVal, err := n.GetTrust(eigenRspnMsg.Source)
	if err != nil {
		return err
	}

	localTrust := eigenRspnMsg.Value
	if eigenRspnMsg.IsPVal {
		localTrust = n.eigenTrust.p
	}

	n.eigenTrust.ReceivedTrustValues.set(eigenRspnMsg.Source, localTrust*peerTrustVal)
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

// func (n *node) GetTrustValue() float64 {
// 	n.eigenTrust.GlobalTrustValueMutex.Lock()
// 	temp := n.eigenTrust.GlobalTrustValue
// 	n.eigenTrust.GlobalTrustValueMutex.Unlock()
// 	return temp
// }
