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
		members: newSafeMap[string, struct{}](),
		votes:   newSafeMap[string, VoteData](),
		currentDial: DialingData{
			ResponseChannel: newResponseChannel(),
		},
	}
}

func (n *node) RequestPK(peer string) error {

	pk := n.GetPK()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pk)
	if err != nil {
		return err
	}

	requestMessage := types.PKRequestMessage{
		PeerId:      n.GetAddress(),
		PubId:       n.crypto.PublicID,
		PubKeyBytes: publicKeyBytes,
	}

	marshalledRequestMessage, err := n.conf.MessageRegistry.MarshalMessage(requestMessage)
	if err != nil {
		return err
	}

	return n.Unicast(peer, marshalledRequestMessage)
}

func (n *node) receivePKRequest(msg types.Message, pkt transport.Packet) error {
	pkRequestMessage, ok := msg.(*types.PKRequestMessage)
	if !ok {
		panic("not a pk request message")
	}

	n.AddPublicKey(pkRequestMessage.PeerId, pkRequestMessage.PubId, pkRequestMessage.PubKeyBytes)

	// Send a response to the peer
	pk := n.GetPK()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pk)
	if err != nil {
		return err
	}

	responseMessage := types.PKResponseMessage{
		PeerId:      n.GetAddress(),
		PubId:       n.crypto.PublicID,
		PubKeyBytes: publicKeyBytes,
	}

	marshalledResponseMessage, err := n.conf.MessageRegistry.MarshalMessage(responseMessage)
	if err != nil {
		return err
	}

	return n.Unicast(pkRequestMessage.PeerId, marshalledResponseMessage)
}

func (n *node) receivePKResponse(msg types.Message, pkt transport.Packet) error {
	pkResponseMessage, ok := msg.(*types.PKResponseMessage)
	if !ok {
		panic("not a pk response message")
	}

	n.AddPublicKey(pkResponseMessage.PeerId, pkResponseMessage.PubId, pkResponseMessage.PubKeyBytes)

	return nil
}

func (n *node) DialPeer(peer string) (string, error) {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	if n.peerCord.currentDial.dialState != types.Idle {
		return "", fmt.Errorf("Peercord is already busy in state %v. Cannot initiate call", n.peerCord.currentDial.dialState)
	}

	// Check that we have a PK for the peer. If not, request it
	_, exists := n.GetPeerKey(peer)
	if !exists {
		n.RequestPK(peer)
	}

	memberList := make([]string, 0, n.peerCord.members.len())
	i := 0
	for member := range n.peerCord.members.internalMap() {
		memberList[i] = member
		i++
	}
	n.peerCord.members.unlock()

	dialMsg := types.DialMsg{
		CallId:  xid.New().String(),
		Caller:  n.GetAddress(),
		PubId:   n.crypto.PublicID,
		Members: memberList,
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(dialMsg)
	if err != nil {
		return "", err
	}

	msgSent := make(chan bool)

	go func() {

		if !exists {
			// We had to send a PK request to the node. Wait for a response first.
			time.Sleep(time.Second)
		}

		encryptedMsg, err := n.EncryptOneToOneMsg(&transpMsg, peer)

		if err != nil {
			msgSent <- false
			n.logger.Err(err)
			return
		}

		err = n.Unicast(peer, *encryptedMsg)
		if err != nil {
			msgSent <- false
			n.logger.Err(err)
			return
		}

		msgSent <- true

	}()

	// Set up the async handler for the dial message
	go func() {
		accepted := false

		if <-msgSent {
			to := time.After(10 * time.Second)

			select {
			case accepted = <-n.peerCord.currentDial.ResponseChannel:
			case <-to:
			}
		}

		n.peerCord.currentDial.Lock()
		defer n.peerCord.currentDial.Unlock()

		if !accepted {
			n.peerCord.currentDial.dialState = types.Idle
		}

		n.peerCord.currentDial.ResponseChannel = newResponseChannel()
	}()

	// We have sucessfully dialed another user
	n.peerCord.currentDial.dialState = types.Dialing
	n.peerCord.currentDial.ID = dialMsg.CallId
	n.peerCord.currentDial.Peer = peer

	return dialMsg.CallId, nil

}

func (n *node) ReceiveDial(msg types.Message, packet transport.Packet) error {
	dialMsg, ok := msg.(*types.DialMsg)
	if !ok {
		panic("not a dial message")
	}

	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	if n.peerCord.currentDial.dialState != types.Idle {
		// We are not idle and we will ignore the dial.
		return nil
	}

	// We have been dialed, ask the user if they want to answer the call
	// TODO: Get the acual trust
	n.logger.Warn().Msg("Received dial, prompting")
	n.logger.Warn().Msg("Received dial, prompting2")
	accepted := n.gui.PromptDial(dialMsg.Caller, 0, 10*time.Second)

	response := types.DialResponseMsg{
		CallId:   dialMsg.CallId,
		PubId:    n.crypto.PublicID,
		Accepted: accepted,
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(response)
	if err != nil {
		return err
	}

	// Check that we have a PK for the peer. If not, request it
	_, exists := n.GetPeerKey(packet.Header.Source)
	if !exists {
		n.RequestPK(packet.Header.Source)
		time.Sleep(time.Second) // Wait for PK response
	}

	encryptedMsg, err := n.EncryptOneToOneMsg(&transpMsg, packet.Header.Source)

	err = n.Unicast(packet.Header.Source, *encryptedMsg)
	if err != nil {
		return err
	}

	if accepted == false {
		n.peerCord.currentDial.dialState = types.Idle
		return nil
	}

	// If we made it here, we have entered a call. Set up the call data
	n.peerCord.currentDial.dialState = types.InCall
	n.peerCord.members.set(dialMsg.Caller, struct{}{})
	n.peerCord.currentDial.IsLeader = false

	return nil
}

func (n *node) ReceiveDialResponse(msg types.Message, packet transport.Packet) error {
	dialResponseMsg, ok := msg.(*types.DialResponseMsg)
	if !ok {
		panic("not a dial message")
	}

	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	if n.peerCord.currentDial.dialState == types.Idle || dialResponseMsg.CallId != n.peerCord.currentDial.ID {
		return fmt.Errorf("received dial response for call not addressed to us")
	}

	expectedID, exists := n.GetPeerKey(packet.Header.Source)
	if !exists {
		return fmt.Errorf("unable to retrieve pub id for %v", packet.Header.Source)
	}

	if packet.Header.Source != n.peerCord.currentDial.Peer || dialResponseMsg.PubId != expectedID.Str {
		return fmt.Errorf("dial reponse is from the wrong source")
	}

	// We received a valid response.
	if dialResponseMsg.Accepted == false {
		// We received a response but we got declined
		n.peerCord.currentDial.ResponseChannel <- false
		return nil
	}

	// If we made it here, we have entered a call. Set up the call data
	n.peerCord.currentDial.dialState = types.InCall
	n.peerCord.members.set(n.peerCord.currentDial.Peer, struct{}{})
	n.peerCord.currentDial.IsLeader = false

	n.peerCord.currentDial.ResponseChannel <- true
	return nil
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
