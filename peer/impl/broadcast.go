package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"math/rand"
	"time"
)

// Send the heartbeat if needed
func (n *node) sendHeartbeat() error {
	if n.conf.HeartbeatInterval != 0 && time.Now().After(n.lastHeartbeat.Add(n.conf.HeartbeatInterval)) {
		n.logger.Info().Msg("sending heartbeat")
		n.lastHeartbeat = time.Now()

		emptyMsg := types.EmptyMessage{}
		marshaledEmptyMsg, err := n.conf.MessageRegistry.MarshalMessage(emptyMsg)
		if err != nil {
			return err
		}

		err = n.Broadcast(marshaledEmptyMsg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't broadcast")
			return err
		}
	}

	return nil
}

// Executes the anti-entropy mechanism if needed
func (n *node) antiEntropy() {
	if n.conf.AntiEntropyInterval != 0 && time.Now().After(n.lastAntiEntropy.Add(n.conf.AntiEntropyInterval)) {
		n.lastAntiEntropy = time.Now()

		// Send the status to a random neighbour if possible
		neighbors := n.routingTable.neighbors(n.GetAddress())

		if len(neighbors) != 0 {
			dest := neighbors[rand.Intn(len(neighbors))]
			n.logger.Info().Str("dest", dest).Msg("using anti-entropy mechanism")
			n.sendStatus(dest)
		}
	}
}

// Sends the status to a neighbor
func (n *node) sendStatus(neighbor string) {
	// Create the status to send
	n.rumorMutex.Lock()
	_, err := n.sendMsgToNeighbor(n.status, neighbor)
	n.rumorMutex.Unlock()

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

	// Send it to a random neighbour
	neighbors := n.routingTable.neighbors(n.GetAddress())

	if len(neighbors) != 0 {
		dest := neighbors[rand.Intn(len(neighbors))]

		err := n.sendRumorsMsg(rumorsMsg, dest)
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
		panic("not a rumors message")
	}

	// Log the message
	n.logger.Info().Str("from", pkt.Header.Source).Msg("rumors received")

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
			next, exists := n.routingTable.get(rumor.Origin)
			if !exists || next != rumor.Origin {
				n.SetRoutingEntry(rumor.Origin, pkt.Header.RelayedBy)
			}

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
	n.logger.Info().Str("dest", pkt.Header.Source).Str("packetID", ack.AckedPacketID).Msg("sending ACK")
	_, err := n.sendMsgToNeighbor(ack, pkt.Header.Source)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send ack to neighbor")
		return err
	}

	// Transfer the rumor to another neighbor if needed and possible
	if hasExpectedRumor {
		dest, ok := n.randomDifferentNeighbor(pkt.Header.Source)

		if ok {
			err := n.sendRumorsMsg(*rumorsMsg, dest)
			if err != nil {
				n.logger.Error().Err(err).Msg("can't send message to neighbor")
				return err
			}
		}
	}

	return nil
}

func (n *node) receiveAck(msg types.Message, pkt transport.Packet) error {
	ackMsg, ok := msg.(*types.AckMessage)
	if !ok {
		panic("not an ACK message")
	}

	// Tell the goroutine in charge of the rumor that we have received the ACK
	n.ackChannelsMutex.Lock()
	channel, exists := n.ackChannels[ackMsg.AckedPacketID]
	n.ackChannelsMutex.Unlock()

	if !exists {
		n.logger.Warn().
			Str("source", pkt.Header.Source).
			Str("Packet ID", ackMsg.AckedPacketID).
			Msg("unexpected ACK received")
		panic("unexpected ACK")
		return nil
	}
	channel <- true

	// Log the ACK
	n.logger.Info().
		Str("source", pkt.Header.Source).
		Str("packet-ID", ackMsg.AckedPacketID).
		Msg("ACK received")

	// Process the status
	err := n.receiveStatus(&ackMsg.Status, pkt)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't receive the status")
		return err
	}

	return nil
}

func (n *node) receiveStatus(msg types.Message, pkt transport.Packet) error {
	statusMsg, ok := msg.(*types.StatusMessage)
	if !ok {
		panic("not a status message")
	}

	n.logger.Info().Str("from", pkt.Header.Source).Msg("received status")

	neighbor := pkt.Header.Source

	// Check if the remote peer has new rumors
	mustSendStatus := false

	n.rumorMutex.Lock()
	for addr, lastSeq := range *statusMsg {
		mySeq, exists := n.status[addr]

		if !exists || mySeq < lastSeq {
			mustSendStatus = true
		}
	}
	n.rumorMutex.Unlock()

	if mustSendStatus {
		n.logger.Info().Msg("processing status: the peer has new rumors")
		n.sendStatus(neighbor)
	}

	// Check if we have rumors that the peer needs
	rumors := types.RumorsMessage{Rumors: make([]types.Rumor, 0)}

	n.rumorMutex.Lock()
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
		n.logger.Info().Int("nb-rumors", len(rumors.Rumors)).Msg("processing status: we have new rumors for the peer")
		err := n.sendRumorsMsg(rumors, neighbor) // TODO we should not expect an ACK here
		if err != nil {
			return err
		}
	}

	// Continue Mongering
	if !mustSendStatus && len(rumors.Rumors) == 0 && rand.Float64() < n.conf.ContinueMongering {
		dest, ok := n.randomDifferentNeighbor(neighbor)
		n.logger.Info().Str("dest", dest).Msg("continue mongering")
		if ok {
			n.sendStatus(dest)
		}
	}

	return nil
}

func (n *node) receiveEmptyMsg(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) receivePrivateMsg(msg types.Message, packet transport.Packet) error {
	privateMsg, ok := msg.(*types.PrivateMessage)
	if !ok {
		panic("not a private message")
	}

	_, exists := privateMsg.Recipients[n.conf.Socket.GetAddress()]
	if exists { // The message is for us
		n.processMessage(*privateMsg.Msg)
	}

	return nil
}

// Sends a rumors message to a neighbor
func (n *node) sendRumorsMsg(msg types.RumorsMessage, neighbor string) error {
	marshaled, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return err
	}

	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), neighbor, 0)
	pkt := transport.Packet{Header: &header, Msg: &marshaled}

	n.logger.Info().Str("packetID", header.PacketID).Str("neighbor", neighbor).Msg("sent rumor to neighbor")

	// Wait for the ACK
	n.ackChannelsMutex.Lock()

	go func() {
		channel := make(chan bool)

		n.ackChannels[header.PacketID] = channel
		n.ackChannelsMutex.Unlock()

		select {
		case <-channel:
			// Do nothing

		case <-time.After(n.conf.AckTimeout):
			n.logger.Info().Str("packetID", header.PacketID).Msg("ACK not received in time")
			newDest, exists := n.randomDifferentNeighbor(neighbor)

			// TODO bug: the channel is deleted afterwards?
			if exists {
				err := n.sendRumorsMsg(msg, newDest)
				if err != nil {
					n.logger.Error().Err(err).Msg("can't transfer the rumor to another neighbor")
				}
			}
		}

		// Delete the channel
		n.ackChannelsMutex.Lock()
		delete(n.ackChannels, header.PacketID)
		n.ackChannelsMutex.Unlock()
	}()

	// Make sure that the channel has been created by the goroutine
	n.ackChannelsMutex.Lock()
	n.ackChannelsMutex.Unlock()

	return n.conf.Socket.Send(neighbor, pkt, time.Second)
}
