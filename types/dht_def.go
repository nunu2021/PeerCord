package types

import (
    "sync"
    "time"
)

type Point [3]uint16

type Zone struct {
    LowerLeft   Point
    UpperRight  Point
}

type SequencedZone struct {
    Zone   Zone
    Number int
}

type RefreshTime struct {
    Mu    sync.Mutex
    Map   map[string]time.Time
}

type BootstrapRequestMessage struct {}

type BootstrapResponseMessage struct {
    IPAddrs      []string
}

type UpdateBootstrapMessage struct {
    Source    string
}

type DHTJoinRequestMessage struct {
    Source      string
    Destination Point
}

type DHTJoinAcceptMessage struct {
    Area       SequencedZone
    Neighbors  map[string]SequencedZone
    Points     map[string]float64
}

type DHTUpdateNeighborsMessage struct {
    Node       string
    NodeArea   SequencedZone
}

type DHTNeighborsStatusMessage struct {
    Node        string
    Area        SequencedZone
    Neighbors   map[string]SequencedZone
}

type DHTSetTrustMessage struct {
    Source     string
    TrustValue float64
    Point      Point
}

type DHTQueryMessage struct {
    Source  string
    Point   Point
}

