package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
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
	dest := n.routingTable.randomNeighbor()

	if dest != "" {
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
