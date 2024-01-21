package impl

import (
	"crypto/x509"
	"math/rand"
	"time"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// Send the heartbeat if needed
func (n *node) sendHeartbeat() error {
	if n.conf.HeartbeatInterval != 0 && time.Now().After(n.lastHeartbeat.Add(n.conf.HeartbeatInterval)) {
		//n.logger.Info().Msg("sending heartbeat")
		n.lastHeartbeat = time.Now()

		pk := n.GetPK()
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pk)

		if err != nil {
			return err
		}

		heartbeatMsg := types.HeartbeatMessage{
			PeerId:      n.GetAddress(),
			PubId:       n.crypto.PublicID,
			PubKeyBytes: publicKeyBytes,
		}

		marshaledHeartbeatMsg, err := n.conf.MessageRegistry.MarshalMessage(heartbeatMsg)
		if err != nil {
			return err
		}

		err = n.Broadcast(marshaledHeartbeatMsg)
		if err != nil {
			return err
		}

		// emptyMsg := types.EmptyMessage{}
		// marshalledEmptyMsg, err := n.conf.MessageRegistry.MarshalMessage(emptyMsg)
		// if err != nil {
		// 	return err
		// }

		// err = n.Broadcast(marshalledEmptyMsg)
		// if err != nil {
		// 	return err
		// }
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
			n.sendStatus(dest)
		}
	}
}

// Sends the status to a neighbor
func (n *node) sendStatus(neighbor string) {
	// Create the status to send
	n.rumorMutex.Lock()
	err := n.sendMsgToNeighbor(n.status, neighbor)
	n.rumorMutex.Unlock()

	if err != nil {
		n.logger.Error().Err(err).Msg("can't send status")
	}
}

// Broadcast implements peer.Messaging
// Broadcast is thread-safe
func (n *node) Broadcast(msg transport.Message) error {
	n.rumorMutex.Lock()

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

	// Create the message
	rumorsMsg := types.RumorsMessage{
		Rumors: []types.Rumor{rumor},
	}

	// Send it to a random neighbour
	neighbors := n.routingTable.neighbors(n.GetAddress())

	if len(neighbors) != 0 {
		dest := neighbors[rand.Intn(len(neighbors))]

		err := n.sendRumorsMsg(rumorsMsg, dest, true)
		if err != nil {
			return err
		}
	}

	n.rumorMutex.Unlock()

	// Process the rumor locally
	select {
	case n.messagesToProcess <- msg:
	default:
		n.logger.Error().Msg("can't add message to process: buffer full")
	}

	return nil
}

func (n *node) receiveRumors(msg types.Message, pkt transport.Packet) error {
	rumorsMsg, ok := msg.(*types.RumorsMessage)
	if !ok {
		panic("not a rumors message")
	}

	// Process the rumors
	hasExpectedRumor := false

	for _, rumor := range rumorsMsg.Rumors {
		n.rumorMutex.Lock()
		previousSequence := n.status[rumor.Origin] // 0 if it doesn't exist

		if rumor.Sequence == previousSequence+1 {
			hasExpectedRumor = true

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
			n.rumorMutex.Unlock()
			n.processMessage(*rumor.Msg)
		} else {
			n.rumorMutex.Unlock()
		}
	}

	// Send back ACK
	n.rumorMutex.Lock()
	defer n.rumorMutex.Unlock()

	ack := types.AckMessage{AckedPacketID: pkt.Header.PacketID, Status: n.status}
	if err := n.sendMsgToNeighbor(ack, pkt.Header.Source); err != nil {
		n.logger.Error().Err(err).Msg("can't send ack to neighbor")
		return err
	}

	// Transfer the rumor to another neighbor if needed and possible
	if hasExpectedRumor {
		if dest, ok := n.randomDifferentNeighbor(pkt.Header.Source); ok {
			if err := n.sendRumorsMsg(*rumorsMsg, dest, true); err != nil {
				n.logger.Error().Err(err).Str("dest", dest).Msg("can't send message to neighbor")
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

	if exists {
		select {
		case channel <- true:
		case <-time.After(100 * time.Millisecond):
			// Avoid blocking if the data is not read from the channel (very unlikely)
			n.logger.Error().Msg("data can't be sent to channel")
		}
	}

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
		err := n.sendRumorsMsg(rumors, neighbor, false)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't send rumor message")
			return err
		}
	}

	// Continue Mongering
	if !mustSendStatus && len(rumors.Rumors) == 0 && rand.Float64() < n.conf.ContinueMongering {
		dest, ok := n.randomDifferentNeighbor(neighbor)
		if ok {
			n.sendStatus(dest)
		}
	}

	return nil
}

func (n *node) receiveEmptyMsg(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) receiveHeartbeatMsg(msg types.Message, pkt transport.Packet) error {
	heartbeatMsg, ok := msg.(*types.HeartbeatMessage)
	if !ok {
		panic("not a heartbeat message")
	}

	// Even if we have seen this peer before, we will just write the key
	n.AddPublicKey(heartbeatMsg.PeerId, heartbeatMsg.PubId, heartbeatMsg.PubKeyBytes)

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
func (n *node) sendRumorsMsg(msg types.RumorsMessage, neighbor string, waitAck bool) error {
	marshaled, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return err
	}

	header := transport.NewHeader(n.GetAddress(), n.GetAddress(), neighbor, 0)
	pkt := transport.Packet{Header: &header, Msg: &marshaled}

	// Wait for the ACK
	if n.conf.AckTimeout != 0 && waitAck {
		n.ackChannelsMutex.Lock()

		go func() {
			channel := make(chan bool)

			n.ackChannels[header.PacketID] = channel
			n.ackChannelsMutex.Unlock()

			select {
			case <-channel:
				// Do nothing

			case <-time.After(n.conf.AckTimeout):
				newDest, exists := n.randomDifferentNeighbor(neighbor)

				if exists {
					err := n.sendRumorsMsg(msg, newDest, true)
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
		n.ackChannelsMutex.Unlock() //nolint:staticcheck // only check that the channel has been created
	}

	return n.conf.Socket.Send(neighbor, pkt, time.Second)
}

func (n *node) marshalAndBroadcast(msg types.Message) error {
	marshaledMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return err
	}

	err = n.Broadcast(marshaledMsg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) marshalAndBroadcastAsPrivate(recipients map[string]struct{}, msg types.Message) error {
	marshaledMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return err
	}

	privateMsh := types.PrivateMessage{
		Recipients: recipients,
		Msg:        &marshaledMsg,
	}

	return n.marshalAndBroadcast(privateMsh)
}
