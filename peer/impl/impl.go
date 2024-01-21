package impl

import (
	"math"
	"math/rand"
	"os"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
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
		mustStop:          make(chan struct{}, 2),
		logger:            logger,
		messagesToProcess: make(chan transport.Message, 100),
		lastHeartbeat:     time.Now().Add(-2 * conf.HeartbeatInterval),   // Start immediately
		lastAntiEntropy:   time.Now().Add(-conf.AntiEntropyInterval / 2), // Start a bit after
		ackChannels:       make(map[string]chan bool),
		status:            make(types.StatusMessage),
		rumorsReceived:    make(map[string][]types.Rumor),
		fileSharing:       NewFileSharing(),
		paxos:             NewPaxos(),
		crypto:            Crypto{KnownPKs: StrStrMap{Map: make(map[string]StrBytesPair)}},
		multicast:         NewMulticast(),
		peerCord:          newPeerCord(),
		streaming:         NewStreaming(),
		eigenTrust:        NewEigenTrust(conf.TotalPeers),
		gui:               nil,
	}

	// Set a random initialized public ID
	n.SetPublicID(RandomPubId())

	if conf.IsBootstrap {
		n.bootstrap = NewBootstrap()
	} else if conf.StartTrust {
		n.dht = NewDHT(conf.BootstrapAddrs)
	}

	// Register the different kinds of messages
	conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.receiveChatMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.receiveRumors)
	conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.receiveAck)
	conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.receiveStatus)
	conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, n.receiveEmptyMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.HeartbeatMessage{}, n.receiveHeartbeatMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, n.receivePrivateMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.DataRequestMessage{}, n.receiveDataRequest)
	conf.MessageRegistry.RegisterMessageCallback(types.DataReplyMessage{}, n.receiveDataReply)
	conf.MessageRegistry.RegisterMessageCallback(types.SearchRequestMessage{}, n.receiveSearchRequest)
	conf.MessageRegistry.RegisterMessageCallback(types.SearchReplyMessage{}, n.receiveSearchReply)
	conf.MessageRegistry.RegisterMessageCallback(
		types.JoinMulticastGroupRequestMessage{}, n.receiveJoinMulticastGroupMessage)
	conf.MessageRegistry.RegisterMessageCallback(
		types.LeaveMulticastGroupRequestMessage{}, n.receiveLeaveMulticastGroupMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.MulticastMessage{}, n.receiveMulticastMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.MulticastGroupExistence{}, n.ExecMulticastGroupExistence)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosPrepareMessage{}, n.receivePaxosPrepareMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosProposeMessage{}, n.receivePaxosProposeMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosAcceptMessage{}, n.receivePaxosAcceptMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PaxosPromiseMessage{}, n.receivePaxosPromiseMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.TLCMessage{}, n.receiveTLCMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.GroupCallDHIndividual{}, n.ExecGroupCallDHIndividual)
	conf.MessageRegistry.RegisterMessageCallback(types.GroupCallDHSharedSecret{}, n.ExecGroupCallDHSharedSecret)
	conf.MessageRegistry.RegisterMessageCallback(types.DHEncryptedPkt{}, n.ExecDHEncryptedPkt)
	conf.MessageRegistry.RegisterMessageCallback(types.O2OEncryptedPkt{}, n.ExecO2OEncryptedPkt)
	conf.MessageRegistry.RegisterMessageCallback(types.GroupCallVotePkt{}, n.ReceiveGroupCallVotePktMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.PKRequestMessage{}, n.receivePKRequest)
	conf.MessageRegistry.RegisterMessageCallback(types.PKResponseMessage{}, n.receivePKResponse)
	conf.MessageRegistry.RegisterMessageCallback(types.DialMsg{}, n.ReceiveDial)
	conf.MessageRegistry.RegisterMessageCallback(types.DialResponseMsg{}, n.ReceiveDialResponse)
	conf.MessageRegistry.RegisterMessageCallback(types.HangUpMsg{}, n.receiveHangUp)
	conf.MessageRegistry.RegisterMessageCallback(types.CallDataMessage{}, n.receiveCallDataMsg)
	conf.MessageRegistry.RegisterMessageCallback(types.EigenTrustRequestMessage{}, n.ExecEigenTrustRequestMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.EigenTrustResponseMessage{}, n.ExecEigenTrustResponseMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.BootstrapRequestMessage{}, n.ExecBootstrapRequestMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.BootstrapResponseMessage{}, n.ExecBootstrapResponseMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.UpdateBootstrapMessage{}, n.ExecUpdateBootstrapMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTJoinRequestMessage{}, n.ExecDHTJoinRequestMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTJoinAcceptMessage{}, n.ExecDHTJoinAcceptMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTUpdateNeighborsMessage{}, n.ExecDHTUpdateNeighborsMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTSetTrustMessage{}, n.ExecDHTSetTrustMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTQueryMessage{}, n.ExecDHTQueryMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTQueryResponseMessage{}, n.ExecDHTQueryResponseMessage)
	conf.MessageRegistry.RegisterMessageCallback(types.DHTNeighborsStatusMessage{}, n.ExecDHTNeighborsStatusMessage)

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
	// To close the worker correctly, the message need to be sent twice
	mustStop chan struct{}

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

	// Information needed for multicasting
	multicast Multicast

	//Cryptography for peer-cord
	crypto Crypto

	// Video and audio streaming
	streaming Streaming

	// Implements the PeerCord interface
	peerCord PeerCord

	// EigenTrust Trust system fora: aValue,
	eigenTrust EigenTrust

	// Information for DHT
	dht DHT

	// Information for bootstrap node
	bootstrap BootstrapNode
	// Interface for the node to request input from the user
	gui types.PeercordGUI
}

// GetAddress returns the address of the node
func (n *node) GetAddress() string {
	return n.conf.Socket.GetAddress()
}

func (n *node) SetGui(gui types.PeercordGUI) {
	n.gui = gui
}

func (n *node) guiReady() bool {
	return n.gui != nil
}

func (n *node) GetDataBlobStore() storage.Store {
	return n.conf.Storage.GetDataBlobStore()
}

func (n *node) GetNamingStore() storage.Store {
	return n.conf.Storage.GetNamingStore()
}

func (n *node) receivePackets(receivedPackets, rumorsPackets chan transport.Packet) {
	for {
		// Receive a packet
		pkt, err := n.conf.Socket.Recv(math.MaxInt64)
		if err != nil {
			n.logger.Warn().Err(err).Msg("failed to receive message")
		}

		// Check if we must exit the function
		select {
		case <-n.mustStop:
			return
		default:
		}

		if pkt.Msg.Type == "rumor" {
			rumorsPackets <- pkt
		} else {
			receivedPackets <- pkt
		}
	}
}

// all peers will compute a new global trust value every 2 minutes
func (n *node) InitiateEigenTrust() {

	for {
		select {
		case <-n.mustStop:
			return
		default:
			if time.Now().UnixMilli()%(n.conf.EigenPulseWait*1000) == 0 {
				_, err := n.ComputeGlobalTrustValue()
				if err != nil {
					return
				}
			}
		}

	}
}

func loop(n *node) {
	timeoutLoop := time.Second
	if n.conf.HeartbeatInterval != 0 {
		timeoutLoop = min(timeoutLoop, n.conf.HeartbeatInterval/10)
	}
	if n.conf.AntiEntropyInterval != 0 {
		timeoutLoop = min(timeoutLoop, n.conf.AntiEntropyInterval/10)
	}
	receivedPackets := make(chan transport.Packet, 1000)
	rumorsPackets := make(chan transport.Packet, 50)

	// Receive packets (this goroutine is not stopped at the end)
	go n.receivePackets(receivedPackets, rumorsPackets)

	go func(c chan transport.Packet) {
		for p := range c {
			n.processPacket(p)
		}
	}(rumorsPackets)

	// TOD: comment this back in for periodic eigentrust updates
	if !n.conf.IsBootstrap {

		go n.InitiateEigenTrust()
	}

	for {
		// Things to do first to avoid blocking
		select {
		case msg := <-n.messagesToProcess:
			n.processMessage(msg)
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
		// Stop the worker if needed
		case <-n.mustStop:
			return

		case msg := <-n.messagesToProcess:
			n.processMessage(msg)

		case pkt := <-receivedPackets:
			// The packet is for us
			go func() {
				if pkt.Header.Destination == n.GetAddress() {
					n.processPacket(pkt)
				} else if pkt.Header.TTL > 0 { // We must transfer the packet
					n.logger.Warn().Msg("Relayed")
					n.transferPacket(pkt)
				} else {
					n.logger.Info().Msg("dropped packet with TTL=0")
				}
			}()

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

	// Initialize streaming components on startup to avoid
	// opening & closing the webcam repeatedly. Camtron does not support
	// opening & closing repeatedly.
	if err := n.initializeStreaming(); err != nil {
		n.logger.Error().Err(err).Msg("failed to initialize streaming")
		return err
	}

	err := n.GenerateKeyPair()
	if err != nil {
		return xerrors.Errorf("error when generating key pair: %v", err)
	}
	n.isRunning = true
	go loop(n)
	if !n.conf.IsBootstrap && n.conf.StartTrust {
		n.AddPeer(n.conf.BootstrapAddrs...)
		err = n.JoinDHT()
		if err != nil {
			return err
		}
		err := n.SetTrust(n.GetAddress(), n.eigenTrust.p)
		if err != nil {
			return err
		}
	}
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// Only stop the peer if it is running

	if !n.isRunning {
		n.logger.Error().Msg("can't stop peer: not running")
		return NotRunningError{}
	}

	n.gui = nil
	if n.CallLineState() != types.Idle {
		n.EndCall()
	}

	if err := n.destroyStreaming(); err != nil {
		n.logger.Error().Err(err).Msg("failed to stop streaming")
		return err
	}

	n.mustStop <- struct{}{}
	n.mustStop <- struct{}{}
	n.mustStop <- struct{}{}
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
	msgType := pkt.Msg.Type
	if _, requiresEncryption := types.EncryptedMsgTypes[msgType]; requiresEncryption {
		n.logger.Warn().Msgf("Received unencrypted msg of type %v. Ignoring", msgType)
		return
	}

	err := n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		n.logger.Warn().Err(err).Msg("failed to process packet")
		n.logger.Warn().Err(err).Msg(pkt.Msg.Type)
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
