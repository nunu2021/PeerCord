package impl

import (
	"errors"
	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"math/rand"
	"os"
	"sync"
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

	// Create the node
	n := &node{
		conf:         conf,
		routingTable: safeRoutingTable{rt: routingTable},
		isRunning:    false,
		mustStop:     make(chan bool, 1),
		logger:       logger,
		status:       make(types.StatusMessage),
	}

	// Register the different kinds of messages
	conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.receiveChatMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.receiveRumors)
	conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.receiveAck)
	conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.receiveStatus)

	conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, func(message types.Message, packet transport.Packet) error {
		return nil
	})

	conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, func(msg types.Message, packet transport.Packet) error {
		privateMsg, ok := msg.(*types.PrivateMessage)
		if !ok {
			n.logger.Error().Msg("not a private message")
			// TODO return error
		}

		_, exists := privateMsg.Recipients[conf.Socket.GetAddress()]
		if exists { // The message is for us
			n.processMessage(*privateMsg.Msg)
		}

		return nil
	})

	return n
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

	// Current status: for each peer, the last rumor ID received by the peer
	// Also contains the last rumor ID sent by the node
	status      types.StatusMessage
	statusMutex sync.Mutex

	// For each node, all the rumors that we have received from it
	rumorsReceived map[string][]types.Rumor
}

// GetAddress returns the address of the node
func (n *node) GetAddress() string {
	return n.conf.Socket.GetAddress()
}

func loop(n *node) {
	lastHeartbeat := time.Now().Add(-2 * n.conf.HeartbeatInterval) // Start the heartbeat immediately
	lastAntiEntropy := time.Now().Add(-2 * n.conf.AntiEntropyInterval)

	timeoutLoop := time.Second
	if n.conf.HeartbeatInterval != 0 {
		timeoutLoop = min(timeoutLoop, n.conf.HeartbeatInterval/10)
	}
	if n.conf.AntiEntropyInterval != 0 {
		timeoutLoop = min(timeoutLoop, n.conf.AntiEntropyInterval/10)
	}

	for {
		// Stop the worker if needed
		select {
		case <-n.mustStop:
			return
		default:
		}

		// Send the heartbeat if needed
		if n.conf.HeartbeatInterval != 0 && time.Now().After(lastHeartbeat.Add(n.conf.HeartbeatInterval)) {
			n.logger.Info().Msg("sending heartbeat")
			lastHeartbeat = time.Now()

			emptyMsg := types.EmptyMessage{}
			marshaledEmptyMsg, err := n.conf.MessageRegistry.MarshalMessage(emptyMsg)
			if err != nil {
				n.logger.Error().Err(err).Msg("can't marshal empty message")
			}

			err = n.Broadcast(marshaledEmptyMsg)
			if err != nil {
				n.logger.Error().Err(err).Msg("can't broadcast")
			}
		}

		// Use the anti-entropy mechanism if needed
		if n.conf.AntiEntropyInterval != 0 && time.Now().After(lastAntiEntropy.Add(n.conf.AntiEntropyInterval)) {
			n.logger.Info().Msg("using anti-entropy mechanism")
			lastAntiEntropy = time.Now()

			// Send the status to a random neighbour if possible
			neighbors := n.routingTable.neighbors(n.GetAddress())

			if len(neighbors) != 0 {
				dest := neighbors[rand.Intn(len(neighbors))]
				n.sendStatus(dest)
			}
		}

		pkt, err := n.conf.Socket.Recv(timeoutLoop)
		if errors.Is(err, transport.TimeoutError(0)) {
			continue
		}
		if err != nil {
			n.logger.Warn().Err(err).Msg("failed to receive message")
		}

		// The packet is for us
		if pkt.Header.Destination == n.GetAddress() {
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

// Wrap a message in a fake packet to process it
func (n *node) processMessage(msg transport.Message) {
	// Wrap the message in a fake paket
	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), n.GetAddress(), 0)
	pkt := transport.Packet{Header: &header, Msg: &msg}

	// Process the packet
	n.processPacket(pkt)
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addresses ...string) {
	for _, addr := range addresses {
		if addr != n.GetAddress() {
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

// Sends a message to a neighbor of the node.
func (n *node) sendMsgToNeighbor(msg types.Message, dest string) error {
	marshaled, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't marshal the message")
		return err
	}

	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), dest, 0)
	pkt := transport.Packet{Header: &header, Msg: &marshaled}

	return n.conf.Socket.Send(dest, pkt, time.Second)
}
