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

	// This mutex must be locked by the proposer before it starts. It then unlocks
	// it immediately. The goal is to prevent a new proposer from being started
	// when the data of the current step is being reset.
	startProposeMtx sync.Mutex

	// For each ID, the number of peers that have already accepted it.
	// Only accessed from the loop goroutine
	nbAcceptedMsgs map[uint]int

	// Promises waiting to be processed
	receivedPromises chan types.PaxosPromiseMessage

	// Notifies when a consensus has been reached.
	// Gives the final value
	consensusReached chan struct{}

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

	// This variable becomes true when the peer has achieved consensus for the current step
	// It is only used from the goroutine processing messages
	achievedConsensus bool
}

func NewPaxos() Paxos {
	return Paxos{
		// The buffers are used to receive the message the peer sends to itself
		receivedPromises: make(chan types.PaxosPromiseMessage, 1),
		nbAcceptedMsgs:   make(map[uint]int),
		consensusReached: make(chan struct{}, 1),
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

func (n *node) waitAvailability() {
	n.paxos.startProposeMtx.Lock()
	n.paxos.startProposeMtx.Unlock()
}

// Blocks until it is known if the proposal is accepted or not
func (n *node) makeProposal(value types.PaxosValue) error {
	n.paxos.proposeMtx.Lock()

	defer func() {
		n.paxos.proposeMtx.Unlock()

		// Clean the channels
		success := true

		for success {
			select {
			case <-n.paxos.receivedPromises:
			case <-n.paxos.consensusReached:
			default:
				success = false
			}
		}
	}()

	id := n.conf.PaxosID

	for {
		success, err := n.makeProposalWithId(value, id)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't make proposal with given ID")
			return err
		}
		if success {
			return nil
		}
		id += n.conf.TotalPeers
	}
}

// Blocks until it is known if the proposal is accepted or not
// Returns if the proposal was a success. If not, we must try with a greater Id
// Returns:
// - 0 if the proposal was a success
// - 1 if another proposal was accepted
// - 2 if we need to retry with a higher ID
func (n *node) makeProposalWithId(value types.PaxosValue, prepareId uint) (bool, error) {
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
		return false, err
	}

	// Receive promises
	keepWaiting := true
	endTime := time.Now().Add(n.conf.PaxosProposerRetry)

	nbPromises := 0

	var acceptedID uint = 0 // If 0, we can propose our value
	var acceptedValue *types.PaxosValue = nil
	for keepWaiting && nbPromises < threshold {
		select {
		case <-n.paxos.consensusReached: // We must start again
			return true, nil

		case promise := <-n.paxos.receivedPromises:
			// Validate the promise here
			if promise.Step != n.paxos.currentStep || promise.ID != prepareId {
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

	// We don't have enough promises, retry with a higher ID
	if nbPromises < threshold {
		return false, nil
	}

	// Propose
	if acceptedValue != nil { // We can not use our own value
		value = *acceptedValue
	}

	proposeMsg := types.PaxosProposeMessage{
		Step:  n.paxos.currentStep,
		ID:    prepareId,
		Value: value,
	}

	err = n.marshalAndBroadcast(proposeMsg)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't broadcast propose message")
		return false, err
	}

	// Wait until consensus is reached
	select {
	case <-n.paxos.consensusReached:
		return true, nil

	case <-time.After(n.conf.PaxosProposerRetry): // No consensus have been reached
		return false, nil
	}
}

func (n *node) receivePaxosPromiseMsg(originalMsg types.Message, pkt transport.Packet) error {
	msg, ok := originalMsg.(*types.PaxosPromiseMessage)
	if !ok {
		panic("not a paxos promise message")
	}

	select {
	case n.paxos.receivedPromises <- *msg:
	case <-time.After(100 * time.Millisecond):
		n.logger.Info().Msg("promise can't be sent to channel")
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

	n.paxos.nbAcceptedMsgs[msg.ID]++

	// A consensus has been reached
	if n.paxos.nbAcceptedMsgs[msg.ID] == n.conf.PaxosThreshold(n.conf.TotalPeers) && !n.paxos.achievedConsensus {
		n.paxos.achievedConsensus = true

		// Compute the block to add
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

		h := sha256.New()
		h.Write([]byte(strconv.Itoa(int(block.Index))))
		h.Write([]byte(msg.Value.UniqID))
		h.Write([]byte(msg.Value.Filename))
		h.Write([]byte(msg.Value.Metahash))
		h.Write(block.PrevHash)
		block.Hash = h.Sum(nil)

		// Broadcast TLC message
		tlcMsg := types.TLCMessage{
			Step:  n.paxos.currentStep,
			Block: block,
		}

		err := n.marshalAndBroadcast(tlcMsg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't broadcast TLC message")
			return err
		}

		// Don't start new propose. The mutex will be unlocked when enough TLC messages have been received.
		n.paxos.startProposeMtx.TryLock()

		// End the current proposer by telling it we reached a consensus
		for !n.paxos.proposeMtx.TryLock() {
			select {
			case n.paxos.consensusReached <- struct{}{}:
			case <-time.After(10 * time.Millisecond):
			}
		}
		n.paxos.proposeMtx.Unlock()
	}

	return nil
}

// When enough TLC messages have been received, adds the block to the blockchain and update the naming store
func (n *node) thresholdTlcReached(isCatchingUp bool) {
	// Prevent another proposer from starting
	n.paxos.startProposeMtx.TryLock()
	defer n.paxos.startProposeMtx.Unlock()

	info := n.paxos.tlcMessages[n.paxos.currentStep]
	msg := info.tlcMsg
	value := msg.Block.Value

	// End the current proposer
	if !n.paxos.proposeMtx.TryLock() {
		// TODO here, the proposer may be already leaving and not listening for this
		n.paxos.consensusReached <- struct{}{}
		n.paxos.proposeMtx.Lock()
	}
	defer n.paxos.proposeMtx.Unlock()

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
	/*if !isCatchingUp && !n.paxos.hasBroadcastedTLC {
		n.paxos.hasBroadcastedTLC = true

		err := n.marshalAndBroadcast(msg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't broadcast TLC message")
		}
	}*/

	// Reset variables
	n.paxos.nbAcceptedMsgs = make(map[uint]int)
	n.paxos.currentStep++
	n.paxos.maxID = 0
	n.paxos.acceptedID = 0
	n.paxos.acceptedValue = nil
	n.paxos.achievedConsensus = false
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
