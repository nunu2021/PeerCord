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

// AlreadyRunningError occurs when trying to start a peer that is already running
type AlreadyRunningError struct{}

// Error implements error. Returns the error string.
func (err AlreadyRunningError) Error() string {
	return fmt.Sprintf("can't start peer: already running")
}

// NotRunningError occurs when trying to stop a peer that is not running
type NotRunningError struct{}

// Error implements error. Returns the error string.
func (err NotRunningError) Error() string {
	return fmt.Sprintf("can't stop peer: not running")
}
