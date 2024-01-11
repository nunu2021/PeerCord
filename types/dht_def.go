package types

type Point [3]uint16

type Zone struct {
    LowerLeft   Point
    UpperRight  Point
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
    Area       Zone
    Neighbors  map[string]Zone
    Points     map[string]float64
}

type DHTUpdateNeighborsMessage struct {
    Node1       string
    Node1Area   Zone
    Node2       string
    Node2Area   Zone
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

