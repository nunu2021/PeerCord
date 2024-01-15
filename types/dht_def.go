package types

import (
    "sync"
    "time"
)

// Point in 3d space
// The order of coordinates
// is [x, y, z]
type Point [3]uint16

// Lower left is the minimum
// x, y, z coordinate of the zone
//
// Upper right is the maximum x, y, z
// coordinate
type Zone struct {
    LowerLeft   Point
    UpperRight  Point
}

// Zone with a sequence number
// representing how many edits have been
// made to the zone
type SequencedZone struct {
    Zone   Zone
    Number int
}

// Map of a node's IP to a timestamp
// of when they last sent a status message
//
// If beyond the "NodeDiscardInterval", we
// assume the node is no longer our neighbor
// and unable to send a status message and
// remove it from our list of neighbors
type RefreshTime struct {
    Mu    *sync.Mutex
    Map   map[string]time.Time
}

// Channels to send the requested trust value
type SafeTrustChans struct {
    Mu    *sync.Mutex
    Map   map[string](chan float64)
}

// Message to notify the bootstrap nodes
// that a node would like to join the CAN
type BootstrapRequestMessage struct {}

// The list of IP addresses of nodes
// currently in the CAN, maintained by the
// bootstrap nodes
type BootstrapResponseMessage struct {
    IPAddrs      []string
}

// Message sent to inform the bootstrap
// nodes of a joined node
type UpdateBootstrapMessage struct {
    Source    string
}

// Message sent by node who wants to join the CAN
// for a specific reality
type DHTJoinRequestMessage struct {
    Source      string
    Reality     int
    Destination Point
}

// Message sent by node who split its zone
// to the node requesting to join
type DHTJoinAcceptMessage struct {
    Reality    int
    Area       SequencedZone
    Neighbors  map[string]SequencedZone
    Points     map[string]float64
}

// Message sent when node informs its neighbors
// about its new zone boundaries
type DHTUpdateNeighborsMessage struct {
    Reality    int
    Node       string
    NodeArea   SequencedZone
}

// A "heartbeat" message sent to a node's
// neighbors about its current neighbors
// and area
type DHTNeighborsStatusMessage struct {
    Reality     int
    Node        string
    Area        SequencedZone
    Neighbors   map[string]SequencedZone
}

// Message sent to set trusts to a
// specific value
type DHTSetTrustMessage struct {
    Reality    int
    Source     string
    TrustValue float64
    Point      Point
}

// Message sent to get a trust value
type DHTQueryMessage struct {
    Reality    int
    Sender     string
    UniqueID   string
    Source     string
    Point      Point
}

// Response containing the requested
// trust value
type DHTQueryResponseMessage struct {
    Reality     int
    UniqueID    string
    TrustValue  float64
}
