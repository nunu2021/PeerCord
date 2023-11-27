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

// NonExistentChunkError occurs when a peer tries to download a file that does
// not appear in its catalog.
type NonExistentChunkError string

func (err NonExistentChunkError) Error() string {
	return "file does not exists: " + string(err)
}

// NameAlreadyExistsError occurs when the Tag function is used with a name that already exists
type NameAlreadyExistsError string

func (err NameAlreadyExistsError) Error() string {
	return "name already exists: " + string(err)
}
