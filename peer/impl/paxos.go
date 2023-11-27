package impl

import (
	"crypto/sha256"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"strconv"
)

type Paxos struct {
	currentStep uint

	// Acceptor
	maxID         uint
	acceptedID    uint
	acceptedValue *types.PaxosValue

	// Listener
	nbAccepted map[string]int // For each UniqID, the number of peers that have already accepted it

	// TLC
	tlcMessages map[uint]struct { // For each step, information about the messages received
		tclMsg types.TLCMessage
		count  int
	}
}

func NewPaxos() Paxos {
	return Paxos{
		currentStep:   0,
		maxID:         0,
		acceptedID:    0,
		acceptedValue: nil,
		nbAccepted:    make(map[string]int),
		tlcMessages: make(map[uint]struct {
			tclMsg types.TLCMessage
			count  int
		}),
	}
}

func (n *node) nextStep() {
	n.paxos.currentStep++
	n.paxos.maxID = 0
	n.paxos.acceptedID = 0
	n.paxos.acceptedValue = nil
	n.paxos.nbAccepted = make(map[string]int)
}

func (n *node) lastBlock() *types.BlockchainBlock {
	blockchain := n.conf.Storage.GetBlockchainStore()

	key := blockchain.Get(storage.LastBlockKey)
	if key == nil {
		return nil
	}

	var block types.BlockchainBlock
	err := block.Unmarshal(blockchain.Get(string(key)))
	if err != nil {
		n.logger.Error().Err(err).Msg("can't unmarshal block from blockchain")
	}
	return &block
}

func (n *node) receivePaxosPrepareMsg(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.PaxosPrepareMessage)
	if !ok {
		panic("not a paxos prepare message")
	}

	// Ignore messages with wrong Step
	if msg.Step != n.paxos.currentStep {
		return nil
	}

	// Ignore messages with too small ID
	if msg.ID <= n.paxos.maxID {
		return nil
	}

	n.paxos.maxID = msg.ID

	// Answer with a promise
	promiseMsg := types.PaxosPromiseMessage{
		Step:          n.paxos.currentStep,
		ID:            n.paxos.maxID,
		AcceptedID:    n.paxos.acceptedID,
		AcceptedValue: n.paxos.acceptedValue,
	}

	recipients := map[string]struct{}{pkt.Header.Source: struct{}{}}

	err := n.marshalAndBroadcastAsPrivate(recipients, promiseMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send promise")
		return err
	}

	return nil
}

func (n *node) receivePaxosProposeMsg(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.PaxosProposeMessage)
	if !ok {
		panic("not a paxos propose message")
	}

	// Check if the message is invalid
	if msg.Step != n.paxos.currentStep || msg.ID != n.paxos.maxID {
		return nil
	}

	// Save the data
	n.paxos.acceptedID = msg.ID
	n.paxos.acceptedValue = &msg.Value

	acceptMsg := types.PaxosAcceptMessage{
		Step:  n.paxos.currentStep,
		ID:    n.paxos.acceptedID,
		Value: *n.paxos.acceptedValue,
	}

	err := n.marshalAndBroadcast(acceptMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast accept message")
		return err
	}

	return nil
}

func (n *node) receivePaxosAcceptMsg(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.PaxosAcceptMessage)
	if !ok {
		panic("not a paxos accept message")
	}

	// Check if the message is invalid
	if msg.Step != n.paxos.currentStep {
		return nil
	}

	// TODO Ignore messages if the proposer is not in Paxos phase 2: what does it mean?

	// Save that a peer accepted the ID
	uniqID := msg.Value.UniqID
	n.paxos.nbAccepted[uniqID] = n.paxos.nbAccepted[uniqID] + 1

	// A consensus has been reached
	if n.paxos.nbAccepted[uniqID] == n.conf.PaxosThreshold(n.conf.TotalPeers) {
		block := types.BlockchainBlock{
			Index:    n.paxos.currentStep,
			Hash:     nil,
			Value:    msg.Value,
			PrevHash: nil, // TODO
		}

		// TODO is it the correct way to compute the hash?
		h := sha256.New()
		h.Write([]byte(strconv.Itoa(int(block.Index))))
		h.Write([]byte(msg.Value.UniqID))
		h.Write([]byte(msg.Value.Filename))
		h.Write([]byte(msg.Value.Metahash))
		h.Write(block.PrevHash)
		block.Hash = h.Sum(nil)

		tlcMsg := types.TLCMessage{
			Step:  n.paxos.currentStep,
			Block: block,
		}

		err := n.marshalAndBroadcast(tlcMsg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't broadcast TLC message")
			return err
		}
	}

	return nil
}

func (n *node) receiveTLCMessage(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.TLCMessage)
	if !ok {
		panic("not a TLC message")
	}

	value := msg.Block.Value

	// Store the message
	info, ok := n.paxos.tlcMessages[msg.Step]
	if !ok {
		info = struct {
			tclMsg types.TLCMessage
			count  int
		}{
			tclMsg: *msg,
			count:  0,
		}

		n.paxos.tlcMessages[msg.Step] = info
	}

	info.count++

	if info.count == n.conf.PaxosThreshold(n.conf.TotalPeers) {
		// Add the block to the blockchain
		blockchain := n.conf.Storage.GetBlockchainStore()
		marshaledBlock, err := msg.Block.Marshal()
		if err != nil {
			n.logger.Error().Err(err).Msg("can't marshal block")
		}
		blockchain.Set(string(msg.Block.Hash), marshaledBlock)
		blockchain.Set(storage.LastBlockKey, msg.Block.Hash)

		// Update the naming store
		if n.GetNamingStore().Get(value.Filename) != nil {
			n.logger.Error().Str("name", value.Filename).Msg("name already exists")
			return NameAlreadyExistsError(value.Filename)
		}
		n.GetNamingStore().Set(value.Filename, []byte(value.Metahash))

		// TODO broadcast the message if needed

		// Go to next step
		n.nextStep()

		// TODO catch up if needed
	}

	return nil
}
