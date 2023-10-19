package impl

import (
	"go.dedis.ch/cs438/transport"
	"time"
)

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), dest, 0)
	pkt := transport.Packet{Header: &header, Msg: &msg}

	next, exists := n.routingTable.get(dest)

	if !exists {
		err := RoutingError{SourceAddr: n.GetAddress(), DestAddr: dest}
		n.logger.Warn().Err(err).Msg("can't send packet: unknown route")
		return err
	}

	return n.conf.Socket.Send(next, pkt, time.Second)
}

// Called when the peer needs to transfer a packet to a neighbour
func (n *node) transferPacket(pkt transport.Packet) {
	// Update the header
	pkt.Header.TTL--
	pkt.Header.RelayedBy = n.GetAddress()

	next, exists := n.routingTable.get(pkt.Header.Destination)
	if !exists {
		err := RoutingError{SourceAddr: n.GetAddress(), DestAddr: pkt.Header.Destination}
		n.logger.Warn().Err(err).Msg("can't transfer packet: unknown route")
		return
	}

	err := n.conf.Socket.Send(next, pkt, time.Second)
	if err != nil {
		n.logger.Warn().Err(err).Msg("failed to transfer packet")
	}
}
