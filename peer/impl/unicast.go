package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
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

func (n *node) receiveChatMessage(msg types.Message, pkt transport.Packet) error {
	chatMsg, ok := msg.(*types.ChatMessage)
	if !ok {
		panic("not a chat message")
	}

	// Log the message
	n.logger.Info().
		Str("from", pkt.Header.Source).
		Str("content", chatMsg.String()).
		Msg("chat message received")

	return nil
}
