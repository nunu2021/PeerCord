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

func (err RoutingError) Error() string {
	return fmt.Sprintf("peer at %s can't route to %s", err.SourceAddr, err.DestAddr)
}

// AlreadyRunningError occurs when trying to start a peer that is already running
type AlreadyRunningError struct{}

func (err AlreadyRunningError) Error() string {
	return "can't start peer: already running"
}

// NotRunningError occurs when trying to stop a peer that is not running
type NotRunningError struct{}

func (err NotRunningError) Error() string {
	return "can't stop peer: not running"
}

// NonexistentFileError occurs when a peer tries to download a file that does
// not appear in its catalog.
type NonexistentFileError string

func (err NonexistentFileError) Error() string {
	return "file does not exists: " + string(err)
}
