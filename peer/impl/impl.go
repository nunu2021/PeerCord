package impl

import (
	"errors"
	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"os"
	"time"
)

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {

	// Choose the log level. No logs if $GLOG=no
	logLevel := zerolog.DebugLevel

	val, isDefined := os.LookupEnv("GLOG")
	if isDefined && val == "no" {
		logLevel = zerolog.Disabled
	}

	// Initialize the logger
	var logger = zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}).Level(logLevel).With().
		Str("peer", conf.Socket.GetAddress()).
		Timestamp().
		Logger()

	routingTable := make(map[string]string)

	// Add an entry to the routing table
	routingTable[conf.Socket.GetAddress()] = conf.Socket.GetAddress()

	return &node{
		conf:         conf,
		routingTable: safeRoutingTable{rt: routingTable},
		isRunning:    false,
		mustStop:     make(chan bool, 1),
		logger:       logger,
	}
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	conf peer.Configuration

	// Indicates whether the peer is currently running
	isRunning bool

	// Channel used to send a message to stop the worker
	mustStop chan bool

	// Routing table of the node
	routingTable safeRoutingTable

	// Logger instance
	logger zerolog.Logger
}

func loop(n *node) {
	for {
		// Stop the worker if needed
		select {
		case <-n.mustStop:
			return
		default:
		}

		pkt, err := n.conf.Socket.Recv(time.Second)
		if errors.Is(err, transport.TimeoutError(0)) {
			continue
		}
		if err != nil {
			n.logger.Warn().Err(err).Msg("failed to receive message")
		}

		// The packet is for us
		if pkt.Header.Destination == n.conf.Socket.GetAddress() {
			n.processPacket(pkt)
		} else if pkt.Header.TTL > 0 { // We must transfer the packet
			n.transferPacket(pkt)
		} else {
			n.logger.Info().Msg("dropped packet with TTL=0")
		}
	}
}

// Start implements peer.Service
func (n *node) Start() error {
	// Only start the peer if it is not already running
	if n.isRunning {
		n.logger.Error().Msg("can't start peer: already running")
		return AlreadyRunningError{}
	}

	n.isRunning = true
	go loop(n)
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// Only stop the peer if it is running
	if !n.isRunning {
		n.logger.Error().Msg("can't stop peer: not running")
		return NotRunningError{}
	}

	n.mustStop <- true
	n.isRunning = false
	return nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	header := transport.NewHeader(
		n.conf.Socket.GetAddress(),
		n.conf.Socket.GetAddress(),
		dest,
		0,
	)
	pkt := transport.Packet{Header: &header, Msg: &msg}

	next, exists := n.routingTable.get(dest)

	if !exists {
		err := RoutingError{SourceAddr: n.conf.Socket.GetAddress(), DestAddr: dest}
		n.logger.Warn().Err(err).Msg("can't send packet: unknown route")
		return err
	}

	return n.conf.Socket.Send(next, pkt, time.Second)
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addresses ...string) {
	for _, addr := range addresses {
		if addr != n.conf.Socket.GetAddress() {
			// We have a new neighbour
			n.routingTable.set(addr, addr)
		}
	}
}

// GetRoutingTable implements peer.Service
// Returns a copy of the  node's routing table
func (n *node) GetRoutingTable() peer.RoutingTable {
	return n.routingTable.cloneRoutingTable()
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	n.routingTable.set(origin, relayAddr)
}

// Called when the peer has received a new packet.
func (n *node) processPacket(pkt transport.Packet) {
	err := n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		n.logger.Warn().Err(err).Msg("failed to process packet")
	}
}

// Called when the peer needs to transfer a packet to a neighbour
func (n *node) transferPacket(pkt transport.Packet) {
	// Update the header
	pkt.Header.TTL--
	pkt.Header.RelayedBy = n.conf.Socket.GetAddress()

	next, exists := n.routingTable.get(pkt.Header.Destination)
	if !exists {
		err := RoutingError{SourceAddr: n.conf.Socket.GetAddress(), DestAddr: pkt.Header.Destination}
		n.logger.Warn().Err(err).Msg("can't transfer packet: unknown route")
		return
	}

	err := n.conf.Socket.Send(next, pkt, time.Second)
	if err != nil {
		n.logger.Warn().Err(err).Msg("failed to transfer packet")
	}
}
