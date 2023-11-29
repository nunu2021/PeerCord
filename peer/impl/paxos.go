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

	/*
	 * Proposer
	 */

	// This mutex is locked when the peer is making a proposal
	proposeMtx sync.Mutex

	// For each UniqID, the number of peers that have already accepted it
	// Only accessed from the loop goroutine
	nbAcceptedMsgs map[string]int

	// Promises waiting to be processed
	receivedPromises chan types.PaxosPromiseMessage

	// Notifies when enough accept messages have been received
	consensusReached chan struct{}

	// Notifies when the proposer must restart due to a change of TLC
	nextTlcStep chan struct{}

	/*
	 * Acceptor
	 */

	maxID         uint
	acceptedID    uint
	acceptedValue *types.PaxosValue

	/*
	 * TLC
	 */

	// For each step, information about the messages received
	tlcMessages map[uint]struct {
		tlcMsg types.TLCMessage
		count  int
	}
	hasBroadcastedTLC bool // TODO protect by mutex, as other variables
}

func NewPaxos() Paxos {
	return Paxos{
		// The buffers are used to receive the message the peer sends to itself
		receivedPromises: make(chan types.PaxosPromiseMessage, 1),
		nbAcceptedMsgs:   make(map[string]int),
		consensusReached: make(chan struct{}, 1),
		nextTlcStep:      make(chan struct{}, 1),
		currentStep:      0,
		maxID:            0,
		acceptedID:       0,
		acceptedValue:    nil,
		tlcMessages: make(map[uint]struct {
			tlcMsg types.TLCMessage
			count  int
		}),
	}
}

// Clean the variables
func (n *node) nextStep() {
	n.paxos.currentStep++
	n.paxos.maxID = 0
	n.paxos.acceptedID = 0
	n.paxos.acceptedValue = nil
	n.paxos.hasBroadcastedTLC = false
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
// Returns if the provided value was accepted by the system
func (n *node) makeProposal(value types.PaxosValue) (bool, error) {
	n.paxos.proposeMtx.Lock()
	defer n.paxos.proposeMtx.Unlock()

	id := n.conf.PaxosID

	res := 2
	for res == 2 {
		r, err := n.makeProposalWithId(value, id)
		n.logger.Debug().Int("return", r).Msg("end proposal with id")
		if err != nil {
			n.logger.Error().Err(err).Msg("can't make proposal with given ID")
			return false, err
		}
		res = r
		id += n.conf.TotalPeers
	}

	return res == 0, nil
}

// Blocks until it is known if the proposal is accepted or not
// Returns:
// - 0 if the proposal was a success
// - 1 if another proposal was accepted
// - 2 if we need to retry with a higher ID
func (n *node) makeProposalWithId(value types.PaxosValue, prepareId uint) (int, error) {
	threshold := n.conf.PaxosThreshold(n.conf.TotalPeers)

	// Prepare
	prepareMsg := types.PaxosPrepareMessage{
		Step:   n.paxos.currentStep,
		ID:     prepareId,
		Source: n.GetAddress(),
	}

	err := n.marshalAndBroadcast(prepareMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast prepare message")
		return -1, err
	}

	// Receive promises
	keepWaiting := true
	endTime := time.Now().Add(n.conf.PaxosProposerRetry)

	nbPromises := 0

	var acceptedID uint = 0 // If 0, we can propose our value
	var acceptedValue *types.PaxosValue = nil
	for keepWaiting && nbPromises < threshold {
		n.logger.Debug().Msg("1")
		select {
		case <-n.paxos.nextTlcStep: // We must start again
			n.nextStep()
			return 1, nil

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
		n.logger.Debug().Msg("2")
	}

	// We don't have enough promises, retry with a higher ID
	if nbPromises < threshold {
		return 2, nil
	}

	// Propose
	id := n.paxos.maxID
	proposedOurOwnValue := true
	if acceptedValue != nil { // We can not use our own value
		value = *acceptedValue
		id = acceptedID
		proposedOurOwnValue = false
	}

	proposeMsg := types.PaxosProposeMessage{
		Step:  n.paxos.currentStep,
		ID:    id,
		Value: value,
	}

	err = n.marshalAndBroadcast(proposeMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast propose message")
		return -1, err
	}

	// Wait until consensus is reached
	select {
	case <-n.paxos.nextTlcStep: // We must start again
		n.nextStep()
		return 1, nil

	case <-n.paxos.consensusReached:
		if proposedOurOwnValue {
			return 0, nil
		} else {
			return 1, nil
		}

	case <-time.After(n.conf.PaxosProposerRetry): // No consensus have been reached
		return 2, nil
	}
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

	n.paxos.nbAcceptedMsgs[msg.Value.UniqID]++

	// A consensus has been reached
	if n.paxos.nbAcceptedMsgs[msg.Value.UniqID] == n.conf.PaxosThreshold(n.conf.TotalPeers) {
		prevHash := n.conf.Storage.GetBlockchainStore().Get(storage.LastBlockKey)
		if prevHash == nil {
			prevHash = make([]byte, 32)
		}

		block := types.BlockchainBlock{
			Index:    n.paxos.currentStep,
			Hash:     nil,
			Value:    msg.Value,
			PrevHash: prevHash,
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

		if n.paxos.proposeMtx.TryLock() {
			n.paxos.proposeMtx.Unlock()
		} else {
			// If a proposer is listening, tell it that we reached a consensus
			n.paxos.consensusReached <- struct{}{}
		}
	}

	// TODO Ignore messages if the proposer is not in Paxos phase 2: what does it mean?

	return nil
}

// When enough TLC messages have been received, adds the block to the blockchain and update the naming store
func (n *node) thresholdTlcReached(isCatchingUp bool) {
	info := n.paxos.tlcMessages[n.paxos.currentStep]

	msg := info.tlcMsg
	value := msg.Block.Value

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
	}
	n.GetNamingStore().Set(value.Filename, []byte(value.Metahash))

	// Broadcast the message if needed
	if !isCatchingUp && !n.paxos.hasBroadcastedTLC {
		n.paxos.hasBroadcastedTLC = true

		err := n.marshalAndBroadcast(msg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't broadcast TLC message")
		}
	}

	// Reset variables
	n.paxos.nbAcceptedMsgs = make(map[string]int)

	if n.paxos.proposeMtx.TryLock() {
		n.nextStep()
		n.paxos.proposeMtx.Unlock()
	} else {
		// Tell the proposer to restart
		// The proposer will call nextStep itself
		n.paxos.nextTlcStep <- struct{}{}
	}
}

func (n *node) receiveTLCMessage(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.TLCMessage)
	if !ok {
		panic("not a TLC message")
	}

	threshold := n.conf.PaxosThreshold(n.conf.TotalPeers)

	// Store the message
	info, ok := n.paxos.tlcMessages[msg.Step]
	if !ok {
		info = struct {
			tlcMsg types.TLCMessage
			count  int
		}{
			tlcMsg: *msg,
			count:  0,
		}
	}

	info.count++
	n.paxos.tlcMessages[msg.Step] = info

	if info.count == threshold && msg.Step == n.paxos.currentStep {
		n.thresholdTlcReached(false)

		// Catch up if needed
		info, ok := n.paxos.tlcMessages[n.paxos.currentStep]
		for ok && info.count >= threshold {
			n.thresholdTlcReached(true)
			info, ok = n.paxos.tlcMessages[n.paxos.currentStep]
		}
	}

	return nil
}
