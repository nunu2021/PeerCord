package impl

import (
    "fmt"
    "math"
    "math/rand"
    "time"
    "strconv"
    "strings"
    "sync"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

// *******************************************
//               Definitions
// *******************************************

var MAXX uint16 = 0xFFFF
var MAXY uint16 = 0xFFFF
var MAXZ uint16 = 0xFFFF

type DHT struct {
    mu              *sync.Mutex
    Area            types.Zone
    Neighbors       map[string]types.Zone
    Points          map[string]float64
    BootstrapAddrs  []string
    BootstrapChan   chan struct{}
}

func NewDHT(bootstrapAddrs []string) DHT {
    z := types.Zone{
        LowerLeft: types.Point([]uint16{0, 0, 0}),
        UpperRight: types.Point([]uint16{MAXX, MAXY, MAXZ}),
    }
    return DHT{
        mu: &sync.Mutex{},
        Area: z,
        Neighbors: make(map[string]types.Zone),
        BootstrapAddrs: bootstrapAddrs,
        BootstrapChan: make(chan struct{}),
    }
}

// *******************************************
//             Helper Functions
// *******************************************

// Given an IP and port of the form A.B.C.D:E
// where A, B, C, and D are 8-bit integers
// and E is a 16 bit integer, we can create a
// hash function that maps this value into 3D
// coordinates (each 16 bit integers) as follows:
//
// X will be calculated as A then D
// Y will be B then the first 8 bits of E
// Z will be C then the last 8 bits of E
func (n *node) Hash(ip string) types.Point {
    splitString := strings.Split(ip, ":")
    ips := strings.Split(splitString[0], ".")
    
    port, err := strconv.ParseUint(splitString[1], 10, 16)
    if err != nil {
        n.logger.Warn().Err(err).Msg("failed to parse port number into uint")
    }

    x1, err := strconv.ParseUint(ips[0], 10, 16)
    if err != nil {
        n.logger.Warn().Err(err).Msg("failed to parse port number into uint")
    }
    x2, err := strconv.ParseUint(ips[3], 10, 16)
    if err != nil {
        n.logger.Warn().Err(err).Msg("failed to parse port number into uint")
    }
    x := (x1 << 8) | x2

    y1, err := strconv.ParseUint(ips[1], 10, 16)
    if err != nil {
        n.logger.Warn().Err(err).Msg("failed to parse port number into uint")
    }
    y2 := (port >> 8) & 0xFF
    y := (y1 << 8) | y2

    z1, err := strconv.ParseUint(ips[2], 10, 16)
    if err != nil {
        n.logger.Warn().Err(err).Msg("failed to parse port number into uint")
    }
    z2 := port & 0xFF
    z := (z1 << 8) | z2

    return types.Point([]uint16{uint16(x), uint16(y), uint16(z)})
}

// Generates a random point
func RandomPoint() types.Point {
    p := types.Point([]uint16{
        uint16(rand.Uint32() & 0xFFFF),
        uint16(rand.Uint32() & 0xFFFF),
        uint16(rand.Uint32() & 0xFFFF),
    })

    return p
}


func RandomAddr(addrs []string) string {
    return addrs[rand.Intn(len(addrs))]
}

// Checks if point is contained within a node's CAN boundaries
//
// The boundary is as follows (for 2D):
// (0,n) --- (n,n)
//   :         :
// (0,0) --- (n,0)
//
// Thus the lower left corresponds to (0, 0) and the upper right
// corresponds to (n, n)
func Contains(z types.Zone, p types.Point) bool {
    ll := z.LowerLeft
    ur := z.UpperRight

    if ll[0] > p[0] || ur[0] < p[0] {
        return false
    } else if ll[1] > p[1] || ur[1] < p[1] {
        return false
    } else if ll[2] > p[2] || ur[2] < p[2] {
        return false
    }

    return true
}

func FindMaxIndex(arr []int) int {
    maxIdx := 0
    maxVal := 0
    for i, v := range arr {
        if v > maxVal {
            maxVal = v
            maxIdx = i
        }
    }
    return maxIdx
}

func Abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}

func (n *node) Split() (types.Zone, types.Zone) {
    zoneLower := n.dht.Area
    zoneUpper := n.dht.Area
    ll := zoneLower.LowerLeft
    ur := zoneUpper.UpperRight
    splitOn := 0

    dists := []int{Abs(int(ll[0]) - int(ur[0])),
                   Abs(int(ll[1]) - int(ur[1])),
                   Abs(int(ll[2]) - int(ur[2]))}

    if dists[0] == dists[1] && dists[1] == dists[2] {
        // splitOn = rand.Intn(3)
        splitOn = 0
    } else if dists[0] == dists[1] && dists[0] > dists[2] {
        // splitOn = rand.Intn(2)
        splitOn = 0
    } else if dists[1] == dists[2] && dists[1] > dists[0] {
        // splitOn = rand.Intn(2) + 1
        splitOn = 1
    } else if dists[0] == dists[2] && dists[0] > dists[1] {
        // splitOn = rand.Intn(2) * 2
        splitOn = 0
    } else {
        splitOn = FindMaxIndex(dists)
    }

    splitCoord := int(dists[splitOn] / 2) + int(ll[splitOn])
    zoneLower.UpperRight[splitOn] = uint16(splitCoord)
    zoneUpper.LowerLeft[splitOn] = uint16(splitCoord + 1)
    return zoneLower, zoneUpper
}


func (n *node) SplitPoints(lowerZone types.Zone, upperZone types.Zone)  (map[string]float64, map[string]float64) {
    lowerPoints := make(map[string]float64)
    upperPoints := make(map[string]float64)
    for node, val := range n.dht.Points {
        if Contains(lowerZone, n.Hash(node)) {
            lowerPoints[node] = val
        } else {
            upperPoints[node] = val
        }
    }
    return lowerPoints, upperPoints
}

func (n *node) Overlap1D(x1 uint16, x2 uint16, y1 uint16, y2 uint16) bool {
    if x2 >= y1 && y2 >= x1 {
        return true
    } else if int(y1) - int(x2) == 1 || int(x1) - int(y2) == 1 {
        return true
    }
    return false
}

func (n *node) BordersZone(z types.Zone, zNew types.Zone) bool {
    ll := z.LowerLeft
    ur := z.UpperRight
    llNew := zNew.LowerLeft
    urNew := zNew.UpperRight
    return n.Overlap1D(ll[0], ur[0], llNew[0], urNew[0]) &&
           n.Overlap1D(ll[1], ur[1], llNew[1], urNew[1]) &&
           n.Overlap1D(ll[2], ur[2], llNew[2], urNew[2])
}


// *******************************************
//           Interface Functions
// *******************************************


func (n *node) JoinDHT() error {
    return n.QueryBootstrap()
}


// Sends message to set trust value
func (n *node) SetTrust(node string, trustValue float64) error {
    point := n.Hash(node)
    msg := types.DHTSetTrustMessage{
        Source: node,
        TrustValue: trustValue,
        Point: point,
    }
    tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
    if err != nil {
        return xerrors.Errorf("error marshalling message %v", msg)
    }
    return n.ForwardCloser(point, &tMsg)
}

// sends message to get trust value
func (n *node) GetTrust(node string) (float64, error) {
    point := n.Hash(node)
    chanTrust := make(chan float64, 1)
    msg := types.DHTQueryMessage{
        Source: node,
        Point: point,
    }
    tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
    if err != nil {
        return 0, xerrors.Errorf("error marshalling message %v", msg)
    }

    err = n.ForwardCloser(point, &tMsg)
    if err != nil {
        return 0, xerrors.Errorf("error routing message %v in dht", msg)
    }

    t := <- chanTrust
    return t, nil
}

// *******************************************
//             Testing Functions
// *******************************************

func (n *node) ReturnDHTArea() types.Zone {
    n.dht.mu.Lock()
    defer n.dht.mu.Unlock()
    return n.dht.Area
}

func (n *node) ReturnDHTNeighbors() map[string]types.Zone {
    n.dht.mu.Lock()
    defer n.dht.mu.Unlock()
    return n.dht.Neighbors
}

func (n *node) ReturnBootstrapNodes() []string {
    n.bootstrap.mu.Lock()
    defer n.bootstrap.mu.Unlock()
    return n.bootstrap.NodeList
}

func (n *node) ReturnDHTPoints() map[string]float64 {
    n.dht.mu.Lock()
    defer n.dht.mu.Unlock()
    return n.dht.Points
}

func (n *node) NeighborsToString() string {
    // n.dht.mu.Lock()
    // defer n.dht.mu.Unlock()
    s := "Neighbors\n------------\n"
    for node, val := range n.dht.Neighbors {
        s = fmt.Sprintf("%s\"%s: %s\",\n", s, node, val.String())
    }
    return s
}

func (n *node) ToString(neighbors map[string]types.Zone) string {
    // n.dht.mu.Lock()
    // defer n.dht.mu.Unlock()
    s := "Neighbors\n------------\n"
    for node, val := range neighbors {
        s = fmt.Sprintf("%s\"%s: %s\",\n", s, node, val.String())
    }
    return s
}

// *******************************************
//           Distributed Hash Table
//  Content Addressed Network Implementation
// *******************************************

func (n *node) QueryBootstrap() error {
    // Send query to bootstrap node
    // If no reply and times out, then try with new node
    msg := types.BootstrapRequestMessage{}
    tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
    if err != nil {
        return xerrors.Errorf("error marshalling message %v", msg)
    }

    for _, b := range n.conf.BootstrapAddrs {
        err := n.Unicast(b, tMsg)
        if err != nil {
            continue
        }

        timer := time.NewTimer(n.conf.BootstrapTimeout)
        in:
        for {
            select {
                case <- timer.C:
                    break in
                case <- n.dht.BootstrapChan:
                    timer.Stop()
                    return nil
            }
        }
    }

    return xerrors.Errorf("no bootstrap nodes available")
}


// Node requests to join the DHT
//
// It should do the following steps:
// - Talk to the bootstrap node
// - Retrieve the CAN information
// - Choose a random point P and request
//   to join that zone
func (n *node) SendDHTJoin(IPAddrs []string) error {
    p := RandomPoint()

    msg := types.DHTJoinRequestMessage{Source: n.GetAddress(), Destination: p}
    tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
    if err != nil {
        return xerrors.Errorf("error marshalling message %v", msg)
    }

    addr := RandomAddr(IPAddrs)
    err = n.Unicast(addr, tMsg)
    if err != nil {
        return xerrors.Errorf("unable to send message: %v", err)
    }

    fmt.Printf("Node %s sent join request to node %s\n", n.GetAddress(), addr)

    return nil
}


func (n *node) ForwardCloser(p types.Point, msg *transport.Message) error {
    n.dht.mu.Lock()
    defer n.dht.mu.Unlock()
    closest := ""
    minDist := math.MaxFloat64
    for neighbor, zone := range n.dht.Neighbors {
        x := float64(max(int(p[0]) - int(zone.UpperRight[0]), 0, int(zone.LowerLeft[0]) - int(p[0])))
        y := float64(max(int(p[1]) - int(zone.UpperRight[1]), 0, int(zone.LowerLeft[1]) - int(p[1])))
        z := float64(max(int(p[2]) - int(zone.UpperRight[2]), 0, int(zone.LowerLeft[2]) - int(p[2])))

        dist := math.Sqrt(math.Pow(x, 2) + math.Pow(y, 2) + math.Pow(z, 2))
        if dist < minDist {
            minDist = dist
            closest = neighbor
        }
    }

    // fmt.Printf("Node %s forwarding join request closer to destination: to node %s\n", n.GetAddress(), closest)

    return n.Unicast(closest, *msg)
}


func (n *node) UpdateBothNeighbors(lowerHalf types.Zone,
                upperHalf types.Zone) map[string]types.Zone {
    lowerNeighbors := make(map[string]types.Zone)
    upperNeighbors := make(map[string]types.Zone)

    for node, zone := range n.dht.Neighbors {
        if n.BordersZone(lowerHalf, zone) {
            lowerNeighbors[node] = zone
        }
        if n.BordersZone(upperHalf, zone) {
            upperNeighbors[node] = zone
        }
    }

    n.dht.Neighbors = lowerNeighbors
    n.dht.Area = lowerHalf
    upperNeighbors[n.GetAddress()] = lowerHalf
    fmt.Printf("Node %s is updating its neighbors to %v (without the joining node's value) and the joining node's neighbors to %v\n", n.GetAddress(), n.NeighborsToString(), n.ToString(upperNeighbors))
    return upperNeighbors
}


func (n *node) UpdateNeighbors(node1 string, node1Area types.Zone,
                               node2 string, node2Area types.Zone) {
    n.dht.mu.Lock()
    defer n.dht.mu.Unlock()
    area := n.dht.Area
    neighbors := n.dht.Neighbors
    neighbors[node1] = node1Area
    neighbors[node2] = node2Area
    newNeighbors := make(map[string]types.Zone)
    for neighbor, zone := range neighbors {
        if n.BordersZone(area, zone) {
            // // TODO: should I move this out?
            // delete(neighbors, neighbor)
            newNeighbors[neighbor] = zone
        }
    }
    n.dht.Neighbors = newNeighbors
    fmt.Printf("Node %s is updating neighbors to %v\n", n.GetAddress(), n.NeighborsToString())
}


// ---------------------------------------
// Process Message Functions
// ---------------------------------------

// Receives request
// If responsible for point, split
// if not responsible, forward
func (n *node) ExecDHTJoinRequestMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTJoinRequestMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

    fmt.Printf("Node %s (%s) received join request from node %s for point %s\n", n.GetAddress(), n.dht.Area.String(), d.Source, d.Destination.String())
    n.routingTable.set(d.Source, d.Source)

    n.dht.mu.Lock()
    if Contains(n.dht.Area, d.Destination) {
        // In zone
        // Find edge to split (split longest)
        lowerHalf, upperHalf := n.Split()
        fmt.Printf("Node %s split zone %v into lower: %v and upper: %v\n", n.GetAddress(), n.dht.Area.String(), lowerHalf.String(), upperHalf.String())
        n.dht.Area = lowerHalf
        fmt.Printf("Node %s has new area: %v\n", n.GetAddress(), n.dht.Area.String())
        // Update neighbors
        originalNeighbors := n.dht.Neighbors
        fmt.Printf("Node %s has original neighbors\n%v\n", n.GetAddress(), n.NeighborsToString())
        upperNeighbors := n.UpdateBothNeighbors(lowerHalf, upperHalf)
        n.dht.Neighbors[d.Source] = upperHalf
        fmt.Printf("Node %s has new neighbors\n%v\n", n.GetAddress(), n.NeighborsToString())
        fmt.Printf("Node %s is given neighbors %v\n", d.Source, upperNeighbors)
        // Update table corresponding to split
        lowerPoints, upperPoints := n.SplitPoints(lowerHalf, upperHalf)
        n.dht.Points = lowerPoints
        // Send neighbors to new node
        acceptMsg := types.DHTJoinAcceptMessage{
            Area: upperHalf, Neighbors: upperNeighbors, Points: upperPoints,
        }
        tAcceptMsg, err := n.conf.MessageRegistry.MarshalMessage(acceptMsg)
        if err != nil {
            n.dht.mu.Unlock()
            return xerrors.Errorf("error marshalling message %v", acceptMsg)
        }
        n.dht.mu.Unlock()
        n.Unicast(d.Source, tAcceptMsg)

        // Send message to all neighbors with new zone
        updateMsg := types.DHTUpdateNeighborsMessage{
            Node1: n.GetAddress(),
            Node1Area: lowerHalf,
            Node2: d.Source,
            Node2Area: upperHalf,
        }
        recipients := make(map[string]struct{})
        for neighbor, _ := range originalNeighbors {
            fmt.Printf("Update neighbor: %s\n", neighbor)
            recipients[neighbor] = struct{}{}
        }
        return n.marshalAndBroadcastAsPrivate(recipients, updateMsg)
    } else {
        n.dht.mu.Unlock()
        return n.ForwardCloser(d.Destination, pkt.Msg)
    }
}

func (n *node) ExecDHTJoinAcceptMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTJoinAcceptMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	fmt.Printf("Node %s received join accept from node %s\n", n.GetAddress(), pkt.Header.Source)
    n.routingTable.set(pkt.Header.Source, pkt.Header.Source)
    for neighbor, _ := range d.Neighbors {
        n.routingTable.set(neighbor, neighbor)
    }
    n.dht.mu.Lock()
	n.dht.Area = d.Area
	n.dht.Points = d.Points
	n.dht.Neighbors = d.Neighbors
    fmt.Printf("Node %s has new area: %v\n", n.GetAddress(), n.dht.Area.String())
    fmt.Printf("Node %s has new neighbors\n%v\n", n.GetAddress(), n.NeighborsToString())
	n.dht.mu.Unlock()

    updateMsg := types.UpdateBootstrapMessage{Source: n.GetAddress()}

    recipients := make(map[string]struct{})
    for _, neighbor := range n.dht.BootstrapAddrs {
        fmt.Println("Neighbor: ", neighbor)
        recipients[neighbor] = struct{}{}
    }
    return n.marshalAndBroadcastAsPrivate(recipients, updateMsg)

	return nil
}

func (n *node) ExecDHTUpdateNeighborsMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTUpdateNeighborsMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

    n.UpdateNeighbors(d.Node1, d.Node1Area, d.Node2, d.Node2Area)
    return nil
}

func (n *node) ExecDHTSetTrustMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTSetTrustMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

    n.dht.mu.Lock()
	if Contains(n.dht.Area, d.Point) {
	    n.dht.Points[d.Source] = d.TrustValue
    } else {
        n.dht.mu.Unlock()
        return n.ForwardCloser(d.Point, pkt.Msg)
    }
    n.dht.mu.Unlock()
    return nil
}

func (n *node) ExecDHTQueryMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTQueryMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	if Contains(n.dht.Area, d.Point) {
        // msg := types.DHTQueryResponseMessage{TrustValue: n.DHT.Points[d.Source]}
        // tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
        // if err != nil {
        //     return xerrors.Errorf("error marshalling message %v", msg)
        // }
	    // n.Unicast(d.Source, tMsg)
	    fmt.Println("Sending...")
	    // d.Channel <- n.dht.Points[d.Source]
    } else {
        return n.ForwardCloser(d.Point, pkt.Msg)
    }
    return nil
}

func (n *node) ExecBootstrapResponseMessage(msg types.Message, pkt transport.Packet) error {
	b, ok := msg.(*types.BootstrapResponseMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.dht.BootstrapChan <- struct{}{}
	if len(b.IPAddrs) > 0 {
        for _, addr := range b.IPAddrs {
            n.routingTable.set(addr, addr)
        }
        fmt.Printf("Node %s sending DHT join\n", n.GetAddress())
        n.SendDHTJoin(b.IPAddrs)
    } else {
        // updateMsg := types.UpdateBootstrapMessage{}

        // recipients := make(map[string]struct{})
        // for _, neighbor := range n.dht.BootstrapAddrs {
        //     recipients[neighbor] = struct{}{}
        // }
        // return n.marshalAndBroadcastAsPrivate(recipients, updateMsg)
    }
	return nil
}
