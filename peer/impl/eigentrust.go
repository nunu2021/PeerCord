package impl

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
    GlobalTrustValue float32

    // probabalistice value to distrubute trust computation between a priori and peers
    a float32

    // a priori distribution
    // no calls can be made if p = 0
    p float32

    // step of global trust value computation 
    // is reset to 0 once global trust value computation complete
    k uint

    // tells whether the peer is currenly in the middle of computing its trust value
    ComputingTrustValue bool

    // map containing a map of the received trust values from CallsOutgoingTo peers
    // the map is mapped with the corresponding k-value
    ReceivedTrustValues safemap[int, safeMap[string, float32]]

}

func NewEigenTrust(float32 aValue, float32 pValue) EigenTrust {
	return EigenTrust{
		IncomingCallCount:               newSafeMap[string, int](),
		IncomingCallRatingSum:  newSafeMap[string, int](),
        CallsOutgoingTo: newSafeMap[string, int](),
        CallsIncomingFrom: newSafeMap[string, int](),
        GlobalTrustValue: 0,
        a: aValue,
        p: pValue,
        k: 0,
        ComputingTrustValue: false,
        ReceivedTrustValues: newSafemap[int, safeMap[string, float32]]


	}
}



// Called after call ends to update peer rating in eigentrust table
func (n* node) EigenRatePeer (string peerIp, int ratingPerCall) {
    n.eigenTrust.IncomingCallCount[peerIp] += 1
    n.eigenTrust.RatingSum[peerIp] += ratingPerCall
}

// processes packet that is requesting this peer's trust value
func (n* node) ExecEigenRequestTrustMessage(){
    
}

// Upon receiving a reponse from peer with peer's trust value for itself
func (n* node) ExecEigenResponseTrustMessage() {

}


// Computes the Global Trust Value for peer
func (n * node) ComputeGlobalTrustValue (string peer){
    ComputingTrustValue = true
    defer ComputingTrustValue = false

    // request t0 from CallsOutgoingTo peers

    // wait till we get all

    // calculate t+1 and store


}