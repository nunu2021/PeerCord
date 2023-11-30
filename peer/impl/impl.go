package impl

import (
	"errors"
	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/storage"
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
		//Caller().
		Logger()

	routingTable := make(map[string]string)

	// Add an entry to the routing table
	routingTable[conf.Socket.GetAddress()] = conf.Socket.GetAddress()

	// Create the node
	n := &node{
		conf:              conf,
		routingTable:      safeRoutingTable{rt: routingTable},
		isRunning:         false,
		mustStop:          make(chan bool, 1),
		logger:            logger,
		messagesToProcess: make(chan transport.Message, 100),
		lastHeartbeat:     time.Now().Add(-2 * conf.HeartbeatInterval),   // Start immediately
		lastAntiEntropy:   time.Now().Add(-conf.AntiEntropyInterval / 2), // Start a bit after
		ackChannels:       make(map[string]chan bool),
		status:            make(types.StatusMessage),
		rumorsReceived:    make(map[string][]types.Rumor),
		fileSharing:       NewFileSharing(),
		paxos:             NewPaxos(),
	}

	// Register the different kinds of messages
	conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.receiveChatMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.receiveRumors)
	conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.receiveAck)
	conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.receiveStatus)
	conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, n.receiveEmptyMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, n.receivePrivateMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.DataRequestMessage{}, n.receiveDataRequest)
	conf.MessageRegistry.RegisterMessageCallback(types.DataReplyMessage{}, n.receiveDataReply)
	conf.MessageRegistry.RegisterMessageCallback(types.SearchRequestMessage{}, n.receiveSearchRequest)
	conf.MessageRegistry.RegisterMessageCallback(types.SearchReplyMessage{}, n.receiveSearchReply)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosPrepareMessage{}, n.receivePaxosPrepareMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosProposeMessage{}, n.receivePaxosProposeMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosAcceptMessage{}, n.receivePaxosAcceptMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosPromiseMessage{}, n.receivePaxosPromiseMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.TLCMessage{}, n.receiveTLCMessage)

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

	// Avoids processing several packets at the same time
	messagesToProcess chan transport.Message

	// Date at which the last heartbeat was sent
	lastHeartbeat time.Time

	// Date at which the last anti-entropy check was realized
	lastAntiEntropy time.Time

	// For each ACK packet that we are waiting for, a channel. When the ACK is
	// received, true is sent to that channel
	ackChannelsMutex sync.Mutex
	ackChannels      map[string]chan bool

	// This mutex must be locked before using status and rumorsReceived
	rumorMutex sync.Mutex

	// Current status: for each peer, the last rumor ID received by the peer
	// Also contains the last rumor ID sent by the node
	status types.StatusMessage

	// For each node, all the rumors that we have received from it
	rumorsReceived map[string][]types.Rumor

	// All the objects used by the file sharing mechanism
	fileSharing FileSharing

	// Information needed to reach consensus with multi-paxos
	paxos Paxos
}

// GetAddress returns the address of the node
func (n *node) GetAddress() string {
	return n.conf.Socket.GetAddress()
}

func (n *node) GetDataBlobStore() storage.Store {
	return n.conf.Storage.GetDataBlobStore()
}

func (n *node) GetNamingStore() storage.Store {
	return n.conf.Storage.GetNamingStore()
}

func loop(n *node) {
	timeoutLoop := time.Second
	if n.conf.HeartbeatInterval != 0 {
		timeoutLoop = min(timeoutLoop, n.conf.HeartbeatInterval/10)
	}
	if n.conf.AntiEntropyInterval != 0 {
		timeoutLoop = min(timeoutLoop, n.conf.AntiEntropyInterval/10)
	}
	receivedPackets := make(chan transport.Packet, 1)

	// Receive packets
	// TODO stop this goroutine at the end
	go func() {
		for {
			// Receive a packet
			// TODO Hour as timeout
			pkt, err := n.conf.Socket.Recv(100 * time.Millisecond)
			//pkt, err := n.conf.Socket.Recv(0)
			if errors.Is(err, transport.TimeoutError(0)) {
				continue
			}
			if err != nil {
				n.logger.Warn().Err(err).Msg("failed to receive message")
			}

			receivedPackets <- pkt
		}
	}()

	for {
		// Things to do first to avoid blocking
		select {
		case msg := <-n.messagesToProcess:
			n.processMessage(msg)
		default:
		}

		// Stop the worker if needed
		select {
		case <-n.mustStop:
			return
		default:
		}

		// Send the heartbeat if needed
		err := n.sendHeartbeat()
		if err != nil {
			n.logger.Error().Err(err).Msg("can't sent heartbeat")
		}

		// Executes the anti-entropy mechanism if needed
		n.antiEntropy()

		select {
		case msg := <-n.messagesToProcess:
			n.processMessage(msg)

		case pkt := <-receivedPackets:
			// The packet is for us
			if pkt.Header.Destination == n.GetAddress() {
				n.processPacket(pkt)
			} else if pkt.Header.TTL > 0 { // We must transfer the packet
				n.transferPacket(pkt)
			} else {
				n.logger.Info().Msg("dropped packet with TTL=0")
			}

		case <-time.After(timeoutLoop):
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
	header := transport.NewHeader("", "", n.GetAddress(), 0)
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

// Sends a message to a neighbor of the node. Returns the ID of the packet sent.
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

// Returns a random neighbor with an address different from the given address
// If such a neighbor exists, returns (addr, true).
// Otherwise, returns ("", false).
func (n *node) randomDifferentNeighbor(forbiddenAddr string) (string, bool) {
	neighbors := n.routingTable.neighbors(n.GetAddress())

	if len(neighbors) < 2 {
		return "", false
	}

	dest := neighbors[rand.Intn(len(neighbors))]
	for dest == forbiddenAddr {
		dest = neighbors[rand.Intn(len(neighbors))]
	}

	return dest, true
}
