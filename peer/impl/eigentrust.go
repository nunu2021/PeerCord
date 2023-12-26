package impl

type EigenTrust struct {
    // total number of calls completed with peer with ip address (string)
    CallCount safeMap[string, int] 
    
    // sum of ratings for all calls completed with peer with ip address (string)
    RatingSum safeMap[string, int] 

    // a priori distribution
    p float32

}

func NewEigenTrust() EigenTrust {
	return EigenTrust{
		CallCount:               newSafeMap[string, map[string]struct{}](),
		RatingSum:  newSafeMap[string, chan struct{}](),
		p: 0,
		
	}
}



// Called after call ends to update peer rating in eigentrust table
func (n* node) EigenRatePeer (string peerIp, int rating) {
    
}

// ExecEigenRequestTrustMessage

// ExecEigenResponseTrustMessage

// Calculate Global Trust Value