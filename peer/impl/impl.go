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
	// here you must return a struct that implements the peer.Peer functions.
	// Therefore, you are free to rename and change it as you want.
	return &node{conf: conf}
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	conf peer.Configuration

	// false by default, becomes true once Stop has been called
	mustStop bool
}

func loop(n *node) {
	for !n.mustStop {
		pkt, err := n.conf.Socket.Recv(time.Second * 1)
		if errors.Is(err, transport.TimeoutError(0)) {
			continue
		}

		if err != nil {
			xerrors.Errorf("failed to receive message: %v", err)
		}

		// The packet is for us
		if pkt.Header.Destination == n.conf.Socket.GetAddress() {
			err := n.conf.MessageRegistry.ProcessPacket(pkt)
			if err != nil {
				xerrors.Errorf("failed to process packet: %v", err)
			}
		} else { // We must transfert the packet
			// TODO update pkt.Header.RelayedBy
			panic("routing not implemented")
		}
	}
}

// Start implements peer.Service
func (n *node) Start() error {
	go loop(n)
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	n.mustStop = true
	return nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	panic("to be implemented in HW0")
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addr ...string) {
	panic("to be implemented in HW0")
}

// GetRoutingTable implements peer.Service
func (n *node) GetRoutingTable() peer.RoutingTable {
	panic("to be implemented in HW0")
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	panic("to be implemented in HW0")
}
