package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"math/rand"
	"time"
)

// Sends the status to a neighbor
func (n *node) sendStatus(neighbor string) {
	// Create the status to send
	n.rumorMutex.Lock()
	marshaledStatus, err := n.conf.MessageRegistry.MarshalMessage(n.status)
	n.rumorMutex.Unlock()
	if err != nil {
		n.logger.Error().Err(err).Msg("can't marshal status")
		// TODO return
	}

	// Send the status to the neighbor
	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), neighbor, 0)
	pkt := transport.Packet{Header: &header, Msg: &marshaledStatus}

	err = n.conf.Socket.Send(neighbor, pkt, time.Second)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send status")
	}
}

// Broadcast implements peer.Messaging
// Broadcast is thread-safe
func (n *node) Broadcast(msg transport.Message) error {
	n.rumorMutex.Lock()
	defer n.rumorMutex.Unlock()

	// Increase the sequence number
	lastSeq, exists := n.status[n.GetAddress()]
	nextSeq := uint(1)
	if exists {
		nextSeq = lastSeq + 1
	}
	n.status[n.GetAddress()] = nextSeq

	// Create the rumor and save it
	rumor := types.Rumor{
		Origin:   n.GetAddress(),
		Sequence: nextSeq,
		Msg:      &msg,
	}

	n.rumorsReceived[n.GetAddress()] = append(n.rumorsReceived[n.GetAddress()], rumor)
	n.logger.Info().Uint("sequence", rumor.Sequence).Msg("started a broadcast")

	// Create the message
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

func (n *node) receiveRumors(msg types.Message, pkt transport.Packet) error {
	n.rumorMutex.Lock()
	defer n.rumorMutex.Unlock()

	rumorsMsg, ok := msg.(*types.RumorsMessage)
	if !ok {
		n.logger.Error().Msg("not a rumors message")
		// TODO return error
	}

	// Log the message
	n.logger.Info().Msg("rumors received")

	// Process the rumors
	hasExpectedRumor := false

	for _, rumor := range rumorsMsg.Rumors {
		previousSequence, exists := n.status[rumor.Origin]
		if !exists {
			previousSequence = 0
		}

		if rumor.Sequence == previousSequence+1 {
			hasExpectedRumor = true

			n.logger.Info().
				Uint("sequence", rumor.Sequence).
				Str("source", rumor.Origin).
				Msg("rumor processed")

			// Update the routing table
			n.SetRoutingEntry(rumor.Origin, pkt.Header.RelayedBy)
			n.logger.Info().
				Str("dest", rumor.Origin).
				Str("next", pkt.Header.RelayedBy).
				Msg("routing table updated")

			// Save the rumor
			if rumor.Sequence == 1 {
				n.rumorsReceived[rumor.Origin] = []types.Rumor{rumor}
			} else {
				n.rumorsReceived[rumor.Origin] = append(n.rumorsReceived[rumor.Origin], rumor)
			}

			// Process it
			n.status[rumor.Origin] = rumor.Sequence
			n.processMessage(*rumor.Msg)
		}
	}

	// Send back ACK
	ack := types.AckMessage{
		AckedPacketID: pkt.Header.PacketID,
		Status:        n.status,
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

	// Transfer the rumor to another neighbor if needed and possible
	if hasExpectedRumor {
		neighbors := n.routingTable.neighbors(n.GetAddress())

		if len(neighbors) > 1 {
			dest := neighbors[rand.Intn(len(neighbors))]
			for dest == ackPkt.Header.Source {
				dest = neighbors[rand.Intn(len(neighbors))]
			}

			marshaledRumors, err := n.conf.MessageRegistry.MarshalMessage(rumorsMsg)
			if err != nil {
				// TODO
			}

			transferredHeader := transport.NewHeader(n.GetAddress(), n.GetAddress(), dest, 0)
			transferredPkt := transport.Packet{Header: &transferredHeader, Msg: &marshaledRumors}

			err = n.conf.Socket.Send(dest, transferredPkt, time.Second)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (n *node) receiveAck(msg types.Message, pkt transport.Packet) error {
	_ /*ackMsg*/, ok := msg.(*types.AckMessage)
	if !ok {
		n.logger.Error().Msg("not an ACK message")
		// TODO return error
	}

	n.logger.Info().Str("source", pkt.Header.Source).Msg("ACK received")

	// TODO

	return nil
}

func (n *node) receiveStatus(msg types.Message, pkt transport.Packet) error {
	statusMsg, ok := msg.(*types.StatusMessage)
	if !ok {
		n.logger.Error().Msg("not a status message")
		// TODO return error
	}

	neighbor := pkt.Header.Source

	n.rumorMutex.Lock()

	// Check if the remote peer has new rumors
	mustSendStatus := false
	for addr, lastSeq := range *statusMsg {
		mySeq, exists := n.status[addr]

		if !exists || mySeq < lastSeq {
			mustSendStatus = true
		}
	}

	if mustSendStatus {
		n.sendStatus(neighbor)
	}

	// Check if we have rumors that the peer needs
	rumors := types.RumorsMessage{Rumors: make([]types.Rumor, 0)}

	for addr, lastSeq := range n.status {
		otherSeq, exists := (*statusMsg)[addr]

		var firstToSend uint
		if !exists {
			firstToSend = 0
		} else {
			firstToSend = otherSeq
		}

		for i := firstToSend; i < lastSeq; i++ {
			rumors.Rumors = append(rumors.Rumors, n.rumorsReceived[addr][i])
		}
	}

	n.rumorMutex.Unlock()

	if len(rumors.Rumors) > 0 {
		err := n.sendMsgToNeighbor(rumors, neighbor)
		if err != nil {
			return err
		}
	}

	// Continue Mongering
	if !mustSendStatus && len(rumors.Rumors) == 0 && rand.Float64() < n.conf.ContinueMongering {
		neighbors := n.routingTable.neighbors(n.GetAddress())

		if len(neighbors) >= 2 {
			dest := neighbors[rand.Intn(len(neighbors))]
			for dest == neighbor {
				dest = neighbors[rand.Intn(len(neighbors))]
			}

			n.sendStatus(dest)
		}
	}

	return nil
}
