package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"strconv"
	"sync"
	"time"
)

type Paxos struct {
	currentStep uint

	// Proposer
	proposeMtx       sync.Mutex // This mutex is unlocked when the peer can make a proposal
	receivedPromises chan types.PaxosPromiseMessage
	receivedAccepts  chan types.PaxosAcceptMessage

	// Acceptor
	maxID         uint
	acceptedID    uint
	acceptedValue *types.PaxosValue

	// TLC
	tlcMessages map[uint]struct { // For each step, information about the messages received
		tclMsg types.TLCMessage
		count  int
	}
}

func NewPaxos() Paxos {
	return Paxos{
		// The buffers are used to receive the message the peer sends to itself
		receivedPromises: make(chan types.PaxosPromiseMessage, 1),
		receivedAccepts:  make(chan types.PaxosAcceptMessage, 1),
		currentStep:      0,
		maxID:            0,
		acceptedID:       0,
		acceptedValue:    nil,
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

	// TODO maybe it is not locked?
	//n.paxos.proposeMtx.Unlock()
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

// Blocks until it is known if the proposal is accepted or not
func (n *node) makeProposal(value types.PaxosValue) error {
	threshold := n.conf.PaxosThreshold(n.conf.TotalPeers)

	// Prepare
	prepareMsg := types.PaxosPrepareMessage{
		Step:   n.paxos.currentStep,
		ID:     n.conf.PaxosID,
		Source: n.GetAddress(),
	}

	err := n.marshalAndBroadcast(prepareMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast prepare message")
		return err
	}

	// Receive promises
	keepWaiting := true
	endTime := time.Now().Add(n.conf.PaxosProposerRetry)

	nbPromises := 0

	var acceptedID uint = 0 // If 0, we can propose our value
	var acceptedValue *types.PaxosValue = nil

	for keepWaiting && nbPromises < threshold {
		select {
		case promise := <-n.paxos.receivedPromises:
			// Validate the promise here
			if promise.Step != n.paxos.currentStep || promise.ID != n.paxos.maxID {
				continue
			}

			// Check if the promise already contains a value
			if promise.AcceptedValue != nil && promise.AcceptedID > acceptedID {
				acceptedID = promise.AcceptedID
				acceptedValue = promise.AcceptedValue
			}

			nbPromises++

		case <-time.After(time.Until(endTime)):
			keepWaiting = false
		}
	}

	// We don't have enough promises, retry
	if nbPromises < threshold {
		// TODO retry with higher ID
		return nil
	}

	// Propose
	id := n.paxos.maxID
	if acceptedValue != nil { // We can not use our own value
		value = *acceptedValue
		id = acceptedID
	}

	proposeMsg := types.PaxosProposeMessage{
		Step:  n.paxos.currentStep,
		ID:    id,
		Value: value,
	}

	err = n.marshalAndBroadcast(proposeMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast propose message")
		return err
	}

	// Receive accept messages
	keepWaiting = true
	endTime = time.Now().Add(n.conf.PaxosProposerRetry)

	nbAcceptedMsgs := make(map[string]int) // For each UniqID, the number of peers that have already accepted it
	//var acceptedValue *types.PaxosValue = nil
	acceptedValue = nil

	for keepWaiting {
		select {
		case acceptMsg := <-n.paxos.receivedAccepts:
			// Validate the promise here
			if acceptMsg.Step != n.paxos.currentStep {
				continue
			}

			nbAcceptedMsgs[acceptMsg.Value.UniqID]++
			if nbAcceptedMsgs[acceptMsg.Value.UniqID] == threshold { // A consensus has been reached
				acceptedValue = &acceptMsg.Value
				keepWaiting = false
			}

		case <-time.After(time.Until(endTime)):
			keepWaiting = false
		}
	}

	// We don't have enough accept messages to reach a consensus, retry
	if acceptedValue == nil {
		// TODO retry with higher ID
		return nil
	}

	// A consensus has been reached
	block := types.BlockchainBlock{
		Index:    n.paxos.currentStep,
		Hash:     nil,
		Value:    *acceptedValue,
		PrevHash: nil, // TODO
	}

	// TODO is it the correct way to compute the hash?
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(int(block.Index))))
	h.Write([]byte(acceptedValue.UniqID))
	h.Write([]byte(acceptedValue.Filename))
	h.Write([]byte(acceptedValue.Metahash))
	h.Write(block.PrevHash)
	block.Hash = h.Sum(nil)

	tlcMsg := types.TLCMessage{
		Step:  n.paxos.currentStep,
		Block: block,
	}

	err = n.marshalAndBroadcast(tlcMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast TLC message")
		return err
	}

	return nil
}

func (n *node) receivePaxosPromiseMsg(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.PaxosPromiseMessage)
	if !ok {
		panic("not a paxos promise message")
	}

	// TODO check that we are in phase 1, waiting for promises

	select {
	case n.paxos.receivedPromises <- *msg:
	case <-time.After(100 * time.Millisecond):
		n.logger.Error().Msg("promise can't be sent to channel")
	}

	return nil
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

	recipients := map[string]struct{}{msg.Source: struct{}{}}

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

	select {
	case n.paxos.receivedAccepts <- *msg:
	case <-time.After(100 * time.Millisecond):
		n.logger.Error().Msg("accept message can't be sent to channel")
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
	}

	info.count++
	n.paxos.tlcMessages[msg.Step] = info

	if info.count == n.conf.PaxosThreshold(n.conf.TotalPeers) && msg.Step == n.paxos.currentStep {
		// Add the block to the blockchain
		blockchain := n.conf.Storage.GetBlockchainStore()
		marshaledBlock, err := msg.Block.Marshal()
		if err != nil {
			n.logger.Error().Err(err).Msg("can't marshal block")
		}
		blockchain.Set(hex.EncodeToString(msg.Block.Hash), marshaledBlock)
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
