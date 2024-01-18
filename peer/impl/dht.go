package impl

import (
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"

	"github.com/rs/xid"
)

// *******************************************
//               Definitions
// *******************************************

var MAXX uint16 = 0xFFFF
var MAXY uint16 = 0xFFFF
var MAXZ uint16 = 0xFFFF

type Reality struct {
	mu            *sync.Mutex
	Area          types.SequencedZone
	Neighbors     map[string]types.SequencedZone
	ResponseChans types.SafeTrustChans
	Points        map[string]float64
	RefreshTimes  types.RefreshTime
}

type DHT struct {
	mu              *sync.Mutex
	BootstrapAddrs  []string
	BootstrapChan   chan struct{}
	BootstrapUpdate map[string]struct{}
	Realities       [5]Reality
}

func NewReality(bootstrapAddrs []string) Reality {
	z := types.Zone{
		LowerLeft:  types.Point([]uint16{0, 0, 0}),
		UpperRight: types.Point([]uint16{MAXX, MAXY, MAXZ}),
	}
	sz := types.SequencedZone{
		Zone:   z,
		Number: 0,
	}
	rt := types.RefreshTime{
		Mu:  &sync.Mutex{},
		Map: make(map[string]time.Time),
	}
	rc := types.SafeTrustChans{
		Mu:  &sync.Mutex{},
		Map: make(map[string](chan float64)),
	}
	return Reality{
		mu:            &sync.Mutex{},
		Area:          sz,
		Neighbors:     make(map[string]types.SequencedZone),
		Points:        make(map[string]float64),
		RefreshTimes:  rt,
		ResponseChans: rc,
	}
}

func NewDHT(bootstrapAddrs []string) DHT {
	d := DHT{
		mu:              &sync.Mutex{},
		Realities:       *new([5]Reality),
		BootstrapAddrs:  bootstrapAddrs,
		BootstrapChan:   make(chan struct{}),
		BootstrapUpdate: make(map[string]struct{}),
	}
	for i := range d.Realities {
		d.Realities[i] = NewReality(bootstrapAddrs)
	}
	return d
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

// Returns a random address given a list of addresses
func RandomAddr(addrs []string) string {
	return addrs[rand.Intn(len(addrs))]
}

// Checks if point is contained within a node's CAN boundaries
//
// The boundary is as follows (for 2D):
// (0,n) --- (n,n)
//
//	:         :
//
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

// Returns the index of the maximum value in the given slice
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

// Returns the absolute value of an int
func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Returns the two halves of the node's area
func (n *node) Split(reality int) (types.Zone, types.Zone) {
	zoneLower := n.dht.Realities[reality].Area.Zone
	zoneUpper := n.dht.Realities[reality].Area.Zone
	ll := zoneLower.LowerLeft
	ur := zoneUpper.UpperRight
	splitOn := 0

	dists := []int{Abs(int(ll[0]) - int(ur[0])),
		Abs(int(ll[1]) - int(ur[1])),
		Abs(int(ll[2]) - int(ur[2]))}

	// Determines which axis to split on based on
	// the length of each edge (splits the maximum)
	// If there are multiple maximums, chooses randomly
	if dists[0] == dists[1] && dists[1] == dists[2] {
		splitOn = rand.Intn(3)
	} else if dists[0] == dists[1] && dists[0] > dists[2] {
		splitOn = rand.Intn(2)
	} else if dists[1] == dists[2] && dists[1] > dists[0] {
		splitOn = rand.Intn(2) + 1
	} else if dists[0] == dists[2] && dists[0] > dists[1] {
		splitOn = rand.Intn(2) * 2
	} else {
		splitOn = FindMaxIndex(dists)
	}

	splitCoord := int(dists[splitOn]/2) + int(ll[splitOn])
	zoneLower.UpperRight[splitOn] = uint16(splitCoord)
	zoneUpper.LowerLeft[splitOn] = uint16(splitCoord + 1)
	return zoneLower, zoneUpper
}

// Splits the points based on the two halves of the zone given
func (n *node) SplitPoints(lowerZone types.Zone, upperZone types.Zone,
	reality int) (map[string]float64,
	map[string]float64) {
	lowerPoints := make(map[string]float64)
	upperPoints := make(map[string]float64)
	for node, val := range n.dht.Realities[reality].Points {
		if Contains(lowerZone, n.Hash(node)) {
			lowerPoints[node] = val
		} else {
			upperPoints[node] = val
		}
	}
	return lowerPoints, upperPoints
}

// Checks whether or not two 1D line segments overlap
func (n *node) Overlap1D(x1 uint16, x2 uint16, y1 uint16, y2 uint16) bool {
	if x2 >= y1 && y2 >= x1 {
		return true
	} else if int(y1)-int(x2) == 1 || int(x1)-int(y2) == 1 {
		return true
	}
	return false
}

// Checks whether or not two zones border each other
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

// Function to join the Dht
func (n *node) JoinDHT() error {
	return n.QueryBootstrap()
}

// Sends message to set trust value
func (n *node) SetTrust(node string, trustValue float64) error {
	for i := 0; i < 5; i++ {
		err := n.SetTrustPerReality(node, trustValue, i)
		if err != nil {
			return err
		}
	}
	return nil
}

// Sets the trust value in each reality
func (n *node) SetTrustPerReality(node string, trustValue float64, reality int) error {
	point := n.Hash(node)
	n.dht.Realities[reality].mu.Lock()
	if Contains(n.dht.Realities[reality].Area.Zone, point) {
		n.dht.Realities[reality].Points[node] = trustValue
		n.dht.Realities[reality].mu.Unlock()
		return nil
	}
	n.dht.Realities[reality].mu.Unlock()
	msg := types.DHTSetTrustMessage{
		Reality:    reality,
		Source:     node,
		TrustValue: trustValue,
		Point:      point,
	}
	tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return xerrors.Errorf("error marshalling message %v", msg)
	}
	return n.ForwardCloser(point, &tMsg, reality)
}

// Sends message to get trust value
func (n *node) GetTrust(node string) (float64, error) {
	trustVals := make(map[float64]int)
	maxCount := 0
	retVal := 0.0

	for i := 0; i < 5; i++ {
		num, err := n.GetTrustPerReality(node, i)
		if err != nil {
			return 0, err
		}
		_, ok := trustVals[num]
		if !ok {
			trustVals[num] = 1
		} else {
			trustVals[num]++
		}
	}

	for trust, count := range trustVals {
		if count > maxCount {
			retVal = trust
		} else if count == maxCount {
			if rand.Float64() < 0.5 {
				retVal = trust
			}
		}
	}
	return retVal, nil
}

// Sends message to each reality to get the trust value of a node
func (n *node) GetTrustPerReality(node string, reality int) (float64, error) {
	n.dht.Realities[reality].mu.Lock()
	val, ok := n.dht.Realities[reality].Points[node]
	if ok {
		n.dht.Realities[reality].mu.Unlock()
		return val, nil
	}

	point := n.Hash(node)
	if Contains(n.dht.Realities[reality].Area.Zone, point) {
		trustVal := n.dht.Realities[reality].Points[node]
		n.dht.Realities[reality].mu.Unlock()
		return trustVal, nil
	}

	n.dht.Realities[reality].mu.Unlock()
	id := xid.New().String()

	n.dht.Realities[reality].ResponseChans.Mu.Lock()
	n.dht.Realities[reality].ResponseChans.Map[id] = make(chan float64)
	chanTrust := n.dht.Realities[reality].ResponseChans.Map[id]
	n.dht.Realities[reality].ResponseChans.Mu.Unlock()

	msg := types.DHTQueryMessage{
		Reality:  reality,
		Sender:   n.GetAddress(),
		UniqueID: id,
		Source:   node,
		Point:    point,
	}
	tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return 0, xerrors.Errorf("error marshalling message %v", msg)
	}

	err = n.ForwardCloser(point, &tMsg, reality)
	if err != nil {
		return 0, xerrors.Errorf("error routing message %v in dht", msg)
	}
	fmt.Println("getting here")
	t := <-chanTrust
	fmt.Println("NOT coming here")

	n.dht.Realities[reality].ResponseChans.Mu.Lock()

	close(n.dht.Realities[reality].ResponseChans.Map[id])
	delete(n.dht.Realities[reality].ResponseChans.Map, id)
	n.dht.Realities[reality].ResponseChans.Mu.Unlock()

	return t, nil
}

// *******************************************
//             Testing Functions
// *******************************************

func (n *node) ReturnDHTArea(reality int) types.Zone {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	return n.dht.Realities[reality].Area.Zone
}

func (n *node) ReturnDHTSequencedArea(reality int) types.SequencedZone {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	return n.dht.Realities[reality].Area
}

func (n *node) ReturnDHTNeighbors(reality int) map[string]types.SequencedZone {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	return n.dht.Realities[reality].Neighbors
}

func (n *node) ReturnBootstrapNodes() []string {
	n.bootstrap.mu.Lock()
	defer n.bootstrap.mu.Unlock()
	return n.bootstrap.NodeList
}

func (n *node) ReturnDHTPoints(reality int) map[string]float64 {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	return n.dht.Realities[reality].Points
}

func (n *node) NeighborsToString(reality int) string {
	s := "Neighbors\n" + "------------\n"
	for node, val := range n.dht.Realities[reality].Neighbors {
		s = fmt.Sprintf("%s\"%s: %s\",\n", s, node, val.String())
	}
	return s
}

func (n *node) NeighborsToStringLocked(reality int) string {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	s := "Neighbors\n------------\n"
	for node, val := range n.dht.Realities[reality].Neighbors {
		s = fmt.Sprintf("%s\"%s: %s\",\n", s, node, val.String())
	}
	return s
}

func (n *node) PointsToString(reality int) string {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	s := "Points\n------------\n"
	for node, val := range n.dht.Realities[reality].Points {
		s = fmt.Sprintf("%s\"%s: %v\",\n", s, node, val)
	}
	return s
}

func (n *node) ToString(neighbors map[string]types.SequencedZone) string {
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

// Queries the bootstrap node
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
			case <-timer.C:
				break in
			case <-n.dht.BootstrapChan:
				timer.Stop()
				return nil
			}
		}
	}

	return xerrors.Errorf("no bootstrap nodes available")
}

// Sends the join request message to each reality
func (n *node) SendDHTJoin(IPAddrs []string) error {
	for i := 0; i < 5; i++ {
		p := RandomPoint()

		msg := types.DHTJoinRequestMessage{Source: n.GetAddress(), Destination: p, Reality: i}
		tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
		if err != nil {
			return xerrors.Errorf("error marshalling message %v", msg)
		}

		addr := RandomAddr(IPAddrs)
		err = n.Unicast(addr, tMsg)
		if err != nil {
			return xerrors.Errorf("unable to send message: %v", err)
		}
	}
	return nil
}

// Forwards a message to a node that is at a closer distance to the
// requesting point
func (n *node) ForwardCloser(p types.Point, msg *transport.Message, reality int) error {
	n.dht.Realities[reality].mu.Lock()
	defer n.dht.Realities[reality].mu.Unlock()
	closest := ""
	minDist := math.MaxFloat64
	for neighbor, zone := range n.dht.Realities[reality].Neighbors {
		x := float64(max(int(p[0])-int(zone.Zone.UpperRight[0]), 0,
			int(zone.Zone.LowerLeft[0])-int(p[0])))
		y := float64(max(int(p[1])-int(zone.Zone.UpperRight[1]), 0,
			int(zone.Zone.LowerLeft[1])-int(p[1])))
		z := float64(max(int(p[2])-int(zone.Zone.UpperRight[2]), 0,
			int(zone.Zone.LowerLeft[2])-int(p[2])))

		dist := math.Sqrt(math.Pow(x, 2) + math.Pow(y, 2) + math.Pow(z, 2))
		if dist < minDist {
			minDist = dist
			closest = neighbor
		}
	}
	return n.Unicast(closest, *msg)
}

// Sends a status message (like the AntiEntropy message)
func (n *node) SendStatus() {
	for i := 0; i < 5; i++ {
		n.dht.Realities[i].mu.Lock()
		if len(n.dht.Realities[i].Neighbors) == 0 {
			n.dht.Realities[i].mu.Unlock()
			return
		}

		n.SendNeighbors(i)
		n.dht.Realities[i].mu.Unlock()
	}
}

// Sends the status to all realities
func (n *node) StartSendingAll() {
	for {
		select {
		case <-n.mustStop:
			return
		default:
			time.Sleep(n.conf.SendNeighborsInterval)
			n.SendStatus()
		}
	}
}

// Starts sending messages to one reality
func (n *node) StartSending(reality int) {
	for {
		select {
		case <-n.mustStop:
			return
		default:
			time.Sleep(n.conf.SendNeighborsInterval)
			n.dht.Realities[reality].mu.Lock()
			if len(n.dht.Realities[reality].Neighbors) == 0 {
				n.dht.Realities[reality].mu.Unlock()
				continue
			}

			n.SendNeighbors(reality)
			n.dht.Realities[reality].mu.Unlock()
		}
	}
}

// Function called when the area of the node changes and must update its neighbors
// to remove ones who are no longer neighbors of the new node
func (n *node) UpdateMyNeighbors(reality int) {
	myZone := n.dht.Realities[reality].Area.Zone
	newNeighbors := make(map[string]types.SequencedZone)
	for neighbor, area := range n.dht.Realities[reality].Neighbors {
		if n.BordersZone(myZone, area.Zone) {
			newNeighbors[neighbor] = area
		}
	}
	n.dht.Realities[reality].Neighbors = newNeighbors
}

// Adds a node to the given map if it borders the node's zone
func (n *node) AddNode(node string, area types.SequencedZone,
	m map[string]types.SequencedZone,
	reality int) map[string]types.SequencedZone {
	if n.BordersZone(n.dht.Realities[reality].Area.Zone, area.Zone) {
		val, ok := m[node]
		if !ok || area.Number > val.Number {
			m[node] = area
		} else {
			m[node] = val
		}
	}
	return m
}

// Gets copy of neighbors
func (n *node) GetNeighborsCopy(reality int) map[string]types.SequencedZone {

	ret := make(map[string]types.SequencedZone)
	for key, val := range n.dht.Realities[reality].Neighbors {
		ret[key] = val
	}
	return ret
}

// Returns the keys of a given map
func (n *node) GetKeys(m map[string]types.SequencedZone) []string {
	i := 0
	keys := make([]string, len(m))
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

// Sends a message to the list of neighbors given
func (n *node) SendToNeighbors(msg types.Message, neighbors []string) error {
	recipients := make(map[string]struct{})
	for _, neighbor := range neighbors {
		recipients[neighbor] = struct{}{}
	}
	return n.marshalAndBroadcastAsPrivate(recipients, msg)
}

// Sends a status message to each neighbor
func (n *node) SendNeighbors(reality int) {
	msg := types.DHTNeighborsStatusMessage{
		Node:      n.GetAddress(),
		Area:      n.dht.Realities[reality].Area,
		Neighbors: n.dht.Realities[reality].Neighbors,
		Reality:   reality,
	}
	_ = n.SendToNeighbors(msg, n.GetKeys(n.dht.Realities[reality].Neighbors))
}

// ---------------------------------------
// Process Message Functions
// ---------------------------------------

func (n *node) ExecDHTJoinRequestMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTJoinRequestMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.routingTable.set(d.Source, d.Source)

	n.dht.Realities[d.Reality].mu.Lock()
	if Contains(n.dht.Realities[d.Reality].Area.Zone, d.Destination) {
		originalNeighbors := n.GetNeighborsCopy(d.Reality)

		// Split zone and points correctly
		half1, half2 := n.Split(d.Reality)
		half1Zone := types.SequencedZone{Zone: half1, Number: 1}
		half2Zone := types.SequencedZone{Zone: half2, Number: 1}
		points1, points2 := n.SplitPoints(half1, half2, d.Reality)

		// Prepare accept message as if we take first half
		acceptMsg := types.DHTJoinAcceptMessage{
			Reality:   d.Reality,
			Area:      half1Zone,
			Neighbors: originalNeighbors,
			Points:    points1,
		}

		// Case on where the point was found
		n.dht.Realities[d.Reality].Area.Number++
		if Contains(half1, d.Destination) {
			n.dht.Realities[d.Reality].Area.Zone = half2
			n.dht.Realities[d.Reality].Neighbors[d.Source] = half1Zone
			n.dht.Realities[d.Reality].Points = points2
		} else {
			n.dht.Realities[d.Reality].Area.Zone = half1
			n.dht.Realities[d.Reality].Neighbors[d.Source] = half2Zone
			n.dht.Realities[d.Reality].Points = points1
			acceptMsg.Area.Zone = half2
			acceptMsg.Points = points2
		}
		acceptMsg.Neighbors[n.GetAddress()] = n.dht.Realities[d.Reality].Area

		// Update neighbors
		n.UpdateMyNeighbors(d.Reality)

		// Send neighbors to new node
		tAcceptMsg, err := n.conf.MessageRegistry.MarshalMessage(acceptMsg)
		if err != nil {
			n.dht.Realities[d.Reality].mu.Unlock()
			return xerrors.Errorf("error marshalling message %v", acceptMsg)
		}
		n.dht.Realities[d.Reality].mu.Unlock()
		err = n.Unicast(d.Source, tAcceptMsg)
		if err != nil {
			return xerrors.Errorf("error unicasting message %v", tAcceptMsg)
		}

		// Send message to all neighbors with new zone
		updateMsg := types.DHTUpdateNeighborsMessage{
			Reality:  d.Reality,
			Node:     n.GetAddress(),
			NodeArea: n.dht.Realities[d.Reality].Area,
		}
		return n.SendToNeighbors(updateMsg, n.GetKeys(originalNeighbors))
	}
	n.dht.Realities[d.Reality].mu.Unlock()
	return n.ForwardCloser(d.Destination, pkt.Msg, d.Reality)
}

func (n *node) ExecDHTJoinAcceptMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTJoinAcceptMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	n.routingTable.set(pkt.Header.Source, pkt.Header.Source)

	// Set values
	n.dht.Realities[d.Reality].mu.Lock()
	n.dht.Realities[d.Reality].Area = d.Area
	n.dht.Realities[d.Reality].Points = d.Points
	n.dht.Realities[d.Reality].Neighbors = d.Neighbors

	// Filter my neighbors
	n.UpdateMyNeighbors(d.Reality)
	for neighbor := range d.Neighbors {
		n.routingTable.set(neighbor, neighbor)
	}
	n.dht.Realities[d.Reality].mu.Unlock()

	// Send an update message to my neighbors
	updateMsg := types.DHTUpdateNeighborsMessage{
		Reality:  d.Reality,
		Node:     n.GetAddress(),
		NodeArea: n.dht.Realities[d.Reality].Area,
	}
	err := n.SendToNeighbors(updateMsg, n.GetKeys(n.dht.Realities[d.Reality].Neighbors))
	if err != nil {
		return xerrors.Errorf("error broadcasting private message: %v", err)
	}

	go n.StartSending(d.Reality)

	n.dht.mu.Lock()
	defer n.dht.mu.Unlock()
	_, ok = n.dht.BootstrapUpdate[n.GetAddress()]
	if !ok {
		n.dht.BootstrapUpdate[n.GetAddress()] = struct{}{}
		bootstrapMsg := types.UpdateBootstrapMessage{Source: n.GetAddress()}
		return n.SendToNeighbors(bootstrapMsg, n.dht.BootstrapAddrs)
	}
	return nil
}

func (n *node) ExecDHTUpdateNeighborsMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTUpdateNeighborsMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	n.dht.Realities[d.Reality].mu.Lock()
	defer n.dht.Realities[d.Reality].mu.Unlock()
	if d.Node == n.GetAddress() {
		return nil
	}

	// Check if the node should be in my neighbors table or not
	if !n.BordersZone(n.dht.Realities[d.Reality].Area.Zone, d.NodeArea.Zone) {
		delete(n.dht.Realities[d.Reality].Neighbors, d.Node)
	} else {
		val, ok := n.dht.Realities[d.Reality].Neighbors[d.Node]
		if !ok || d.NodeArea.Number > val.Number {
			n.dht.Realities[d.Reality].Neighbors[d.Node] = d.NodeArea
		}
	}
	return nil
}

// Checks for stale neighbors
// If a neighbor has not sent a message in NodeDiscardInterval
// time, then we delete the node from our neighbors list
//
// Default = 3s
func (n *node) CheckAndRefresh(reality int) {
	n.dht.Realities[reality].RefreshTimes.Mu.Lock()
	defer n.dht.Realities[reality].RefreshTimes.Mu.Unlock()
	curTime := time.Now()
	for node, prevTime := range n.dht.Realities[reality].RefreshTimes.Map {
		if curTime.Sub(prevTime) > n.conf.NodeDiscardInterval {
			delete(n.dht.Realities[reality].Neighbors, node)
		} else {
			n.dht.Realities[reality].RefreshTimes.Map[node] = curTime
		}
	}
}

func (n *node) ExecDHTNeighborsStatusMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTNeighborsStatusMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	n.dht.Realities[d.Reality].mu.Lock()
	defer n.dht.Realities[d.Reality].mu.Unlock()

	newNeighbors := make(map[string]types.SequencedZone)
	newNeighbors = n.AddNode(d.Node, d.Area, newNeighbors, d.Reality)

	// Add the newest values for the inputted neighbors
	for node, area := range d.Neighbors {
		if node == n.GetAddress() {
			continue
		}
		newNeighbors = n.AddNode(node, area, newNeighbors, d.Reality)
	}

	// Add my neighbors
	for node, area := range n.dht.Realities[d.Reality].Neighbors {
		newNeighbors = n.AddNode(node, area, newNeighbors, d.Reality)
	}
	n.dht.Realities[d.Reality].Neighbors = newNeighbors
	n.CheckAndRefresh(d.Reality)
	return nil
}

func (n *node) ExecDHTSetTrustMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTSetTrustMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.dht.Realities[d.Reality].mu.Lock()
	if Contains(n.dht.Realities[d.Reality].Area.Zone, d.Point) {
		n.dht.Realities[d.Reality].Points[d.Source] = d.TrustValue
	} else {
		n.dht.Realities[d.Reality].mu.Unlock()
		return n.ForwardCloser(d.Point, pkt.Msg, d.Reality)
	}
	n.dht.Realities[d.Reality].mu.Unlock()
	return nil
}

func (n *node) ExecDHTQueryMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTQueryMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.dht.Realities[d.Reality].mu.Lock()
	if Contains(n.dht.Realities[d.Reality].Area.Zone, d.Point) {
		msg := types.DHTQueryResponseMessage{
			Reality:    d.Reality,
			UniqueID:   d.UniqueID,
			TrustValue: n.dht.Realities[d.Reality].Points[d.Source],
		}
		n.dht.Realities[d.Reality].mu.Unlock()
		tMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
		if err != nil {
			return xerrors.Errorf("error marshalling message %v", msg)
		}

		return n.Unicast(d.Sender, tMsg)
	}
	n.dht.Realities[d.Reality].mu.Unlock()
	return n.ForwardCloser(d.Point, pkt.Msg, d.Reality)
}

func (n *node) ExecDHTQueryResponseMessage(msg types.Message, pkt transport.Packet) error {
	d, ok := msg.(*types.DHTQueryResponseMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}
	n.dht.Realities[d.Reality].ResponseChans.Mu.Lock()
	n.dht.Realities[d.Reality].ResponseChans.Map[d.UniqueID] <- d.TrustValue
	n.dht.Realities[d.Reality].ResponseChans.Mu.Unlock()
	return nil
}

func (n *node) ExecBootstrapResponseMessage(msg types.Message, pkt transport.Packet) error {
	b, ok := msg.(*types.BootstrapResponseMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.dht.BootstrapChan <- struct{}{}
	// Check whether or not there are other nodes in the CAN yet
	if len(b.IPAddrs) > 0 {
		for _, addr := range b.IPAddrs {
			n.routingTable.set(addr, addr)
		}
		err := n.SendDHTJoin(b.IPAddrs)
		if err != nil {
			return xerrors.Errorf("error sending join: %v", err)
		}
	} else {
		go n.StartSendingAll()
	}
	return nil
}
