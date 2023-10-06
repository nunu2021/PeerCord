package impl

import (
	"errors"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"golang.org/x/xerrors"
	"time"
)

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	routingTable := make(map[string]string)

	// Add an entry to the routing table
	routingTable[conf.Socket.GetAddress()] = conf.Socket.GetAddress()

	return &node{
		conf:         conf,
		routingTable: safeRoutingTable{rt: routingTable},
		isRunning:    false,
		mustStop:     make(chan bool, 1),
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
}

func loop(n *node) {
	for {
		// Stop the worker if needed
		select {
		case <-n.mustStop:
			return
		default:
		}

		pkt, err := n.conf.Socket.Recv(time.Second * 1)
		if errors.Is(err, transport.TimeoutError(0)) {
			continue
		}

		if err != nil {
			xerrors.Errorf("failed to receive message: %v", err)
		}

		dest := pkt.Header.Destination

		// The packet is for us
		if dest == n.conf.Socket.GetAddress() {
			err := n.conf.MessageRegistry.ProcessPacket(pkt)
			if err != nil {
				xerrors.Errorf("failed to process packet: %v", err)
			}
		} else if pkt.Header.TTL > 0 { // We must transfer the packet
			// Update the header
			pkt.Header.TTL--
			pkt.Header.RelayedBy = n.conf.Socket.GetAddress()

			next, isMissing := n.routingTable.get(dest)
			if isMissing {
				xerrors.Errorf("can't transfer packet: unknown route") // TODO not an error, only log
				continue
			}

			err := n.conf.Socket.Send(next, pkt, time.Second)
			if err != nil {
				xerrors.Errorf("failed to transfer packet: %v", err)
			}
			panic("routing not implemented")
		}
	}
}

// Start implements peer.Service
func (n *node) Start() error {
	// Only start the peer if it is not already running
	// TODO error otherwise?
	if !n.isRunning {
		n.isRunning = true
		go loop(n)
	}
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	n.mustStop <- true
	n.isRunning = false
	return nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	header := transport.NewHeader(n.conf.Socket.GetAddress(), "", dest, 0)
	pkt := transport.Packet{Header: &header, Msg: &msg}

	next, isMissing := n.routingTable.get(dest)

	if isMissing {
		panic("TODO")
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
