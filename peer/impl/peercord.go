package impl

import (
	"crypto/x509"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type DialingData struct {
	sync.Mutex

	dialState types.DialState
	ID        string
	Peer      string

	ResponseChannel chan bool

	IsLeader bool
}

func newResponseChannel() chan bool {
	return make(chan bool, 1)
}

type PeerCord struct {

	// Public Identity
	PubId string

	// List of members in our call
	members safeMap[string, struct{}]

	// A map of votes and the results
	votes safeMap[string, VoteData]

	// The current dialing process
	currentDial DialingData
}

func RandomPubId() string {
	return fmt.Sprintf("+41%010d", rand.Int()%int(10e9))
}

func newPeerCord() PeerCord {
	return PeerCord{
		PubId:   RandomPubId(),
		members: newSafeMap[string, struct{}](),
		votes:   newSafeMap[string, VoteData](),
		currentDial: DialingData{
			ResponseChannel: newResponseChannel(),
		},
	}
}

func (n *node) DialPeer(peer string) (string, error) {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	if n.peerCord.currentDial.dialState != types.Idle {
		return "", fmt.Errorf("Peercord is already busy in state %v. Cannot initiate call", n.peerCord.currentDial.dialState)
	}

	pk := n.GetPK()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pk)
	if err != nil {
		return "", err
	}

	dialMsg := types.DialMsg{
		CallId:         xid.New().String(),
		Caller:         n.GetAddress(),
		PubId:          n.peerCord.PubId,
		PublicKeyBytes: publicKeyBytes,
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(dialMsg)
	if err != nil {
		return "", err
	}

	err = n.Unicast(peer, transpMsg)
	if err != nil {
		return "", err
	}

	// We have sucessfully dialed another user
	n.peerCord.currentDial.dialState = types.Dialing
	n.peerCord.currentDial.ID = dialMsg.CallId
	n.peerCord.currentDial.Peer = peer

	// Set up the async handler for the dial message
	go func() {
		to := time.After(2 * time.Second)

		var accepted bool

		select {
		case accepted = <-n.peerCord.currentDial.ResponseChannel:
		case <-to:
		}

		n.peerCord.currentDial.Lock()
		defer n.peerCord.currentDial.Unlock()

		if !accepted {
			n.peerCord.currentDial.dialState = types.Idle
		}

		n.peerCord.currentDial.ResponseChannel = newResponseChannel()
	}()

	return dialMsg.CallId, nil
}

func (n *node) ReceiveDial(msg types.Message, packet transport.Packet) error {
	dialMsg, ok := msg.(*types.DialMsg)
	if !ok {
		panic("not a dial message")
	}

	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	var initiated bool

	switch n.peerCord.currentDial.dialState {
	case types.Idle:
		// We have been dialed. Respond accordingly
		if !n.PromptDial(dialMsg.Caller) {
			// We declined so we ignore
			// TODO: We could send a decline somehow? types.HangUpMsg
			return nil
		}

		pk := n.GetPK()
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pk)
		if err != nil {
			return err
		}

		response := types.DialMsg{
			CallId:         dialMsg.CallId,
			Caller:         n.GetAddress(),
			PubId:          n.peerCord.PubId,
			PublicKeyBytes: publicKeyBytes,
		}

		transpMsg, err := n.conf.MessageRegistry.MarshalMessage(response)
		if err != nil {
			return err
		}

		err = n.Unicast(packet.Header.Source, transpMsg)
		if err != nil {
			return err
		}

		// We sent an adequete response. We are in a call
		initiated = false

	case types.Dialing:
		// We have received a response. Check if it is for our current dial
		if dialMsg.CallId != n.peerCord.currentDial.ID || packet.Header.Source != n.peerCord.currentDial.Peer {
			n.logger.Warn().Msgf("Received a call from %v while already dialing other node", dialMsg.Caller)
			return nil
		}

		// We have received an adequete response. We are in a call
		initiated = true

	case types.InCall:
		// We are already in a call, we can ignore the message.
		return nil
	}

	// If we made it here, we have entered a call. Process the dial msg data
	n.AddPublicKey(dialMsg.Caller, dialMsg.PubId, dialMsg.PublicKeyBytes)

	n.peerCord.currentDial.ResponseChannel <- true

	n.peerCord.currentDial.dialState = types.InCall
	n.peerCord.members.set(dialMsg.Caller, struct{}{})
	n.peerCord.currentDial.IsLeader = initiated // If we initiated the call, we are the leader

	return nil
}

func (n *node) PromptDial(caller string) bool {
	// TODO: Make decision on trust and GUI
	return true
}

func (n *node) EndCall() {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	n.peerCord.currentDial.dialState = types.Idle
	n.peerCord.members = newSafeMap[string, struct{}]()
	n.peerCord.currentDial.ResponseChannel = newResponseChannel()
}

func (n *node) CallLineState() types.DialState {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	return n.peerCord.currentDial.dialState
}

func (n *node) GetGroupCallMembers() map[string]struct{} {
	copyMemberMap := make(map[string]struct{})

	myMemberMap := n.peerCord.members.internalMap()
	defer n.peerCord.members.unlock()

	for k := range myMemberMap {
		copyMemberMap[k] = struct{}{}
	}

	return copyMemberMap
}
