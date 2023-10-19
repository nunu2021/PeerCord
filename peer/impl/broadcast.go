package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"math/rand"
	"time"
)

// Broadcast implements peer.Messaging
func (n *node) Broadcast(msg transport.Message) error {
	// Create the rumor
	rumor := types.Rumor{
		Origin:   n.GetAddress(),
		Sequence: n.nextSequence,
		Msg:      &msg,
	}
	n.nextSequence++

	n.logger.Info().Uint("sequence", rumor.Sequence).Msg("started a broadcast")

	rumorsMsg := types.RumorsMessage{
		Rumors: []types.Rumor{rumor},
	}

	marshaledRumors, err := n.conf.MessageRegistry.MarshalMessage(rumorsMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't marshal the rumors message")
		return err
	}

	// Send it to a random neighbour
	neighbors := n.routingTable.neighbors(n.GetAddress())

	if len(neighbors) != 0 {
		dest := neighbors[rand.Intn(len(neighbors))]

		header := transport.NewHeader(n.GetAddress(), n.GetAddress(), dest, 0)
		pkt := transport.Packet{Header: &header, Msg: &marshaledRumors}

		err := n.conf.Socket.Send(dest, pkt, time.Second)
		if err != nil {
			return err
		}
	} else {
		n.logger.Info().Msg("no neighbor to transfer the rumor to")
	}

	// Process the rumor locally
	n.processMessage(msg)

	return nil
}

func (n *node) receiveRumor(msg types.Message, pkt transport.Packet) error {
	rumorMsg, ok := msg.(*types.RumorsMessage)
	if !ok {
		n.logger.Error().Msg("not a rumors message")
		// TODO return error
	}

	// Log the message
	n.logger.Info().Msg("rumor received")

	for _, rumor := range rumorMsg.Rumors {

		n.processMessage(*rumor.Msg)
	}

	// Send ACK
	ack := types.AckMessage{
		AckedPacketID: pkt.Header.PacketID,
		Status:        n.statusMessage,
	}

	marshaled, err := n.conf.MessageRegistry.MarshalMessage(ack)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't marshal the ACK message")
		// TODO return error
	}

	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), pkt.Header.Source, 0)
	ackPkt := transport.Packet{Header: &header, Msg: &marshaled}

	err = n.conf.Socket.Send(pkt.Header.Source, ackPkt, time.Second)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send packet")
		// TODO return error
	}

	// TODO transfer rumor

	return nil
}

func (n *node) receiveAck(msg types.Message, pkt transport.Packet) error {
	_ /*ackMsg*/, ok := msg.(*types.AckMessage)
	if !ok {
		n.logger.Error().Msg("not an ACK message")
		// TODO return error
	}

	n.logger.Info().Str("source", pkt.Header.Source).Msg("ACK received")

	return nil
}
