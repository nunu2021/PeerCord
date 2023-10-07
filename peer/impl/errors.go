package impl

import (
	"fmt"
)

// RoutingError occurs when a peer has to relay a packet to a destination that
// does not appear in the routing table
type RoutingError struct {
	SourceAddr string
	DestAddr   string
}

// Error implements error. Returns the error string.
func (err RoutingError) Error() string {
	return fmt.Sprintf("peer at %s can't route to %s", err.SourceAddr, err.DestAddr)
}
