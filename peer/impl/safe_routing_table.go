package impl

import (
	"go.dedis.ch/cs438/peer"
	"sync"
)

// Basic thread-safe (string -> string) map
type safeRoutingTable struct {
	mutex sync.Mutex
	rt    peer.RoutingTable
}

// Safely get a value of the routing table
func (srt *safeRoutingTable) get(key string) (string, bool) {
	srt.mutex.Lock()
	defer srt.mutex.Unlock()

	val, err := srt.rt[key]
	return val, err
}

// Safely set a value of the routing table
func (srt *safeRoutingTable) set(key, val string) {
	srt.mutex.Lock()
	defer srt.mutex.Unlock()

	if val == "" { // Delete the entry
		delete(srt.rt, key)
	} else {
		srt.rt[key] = val
	}
}

// Returns a copy of the internal routing table
func (srt *safeRoutingTable) cloneRoutingTable() peer.RoutingTable {
	srt.mutex.Lock()
	defer srt.mutex.Unlock()

	routingTable := make(map[string]string)

	for key, val := range srt.rt {
		routingTable[key] = val
	}

	return routingTable
}
