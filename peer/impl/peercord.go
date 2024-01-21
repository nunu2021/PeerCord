package impl

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

type DialingData struct {
	sync.Mutex

	dialState types.DialState
	ID        string
	Peer      string

	ResponseChannel chan bool

	leader string

	multicastGroupID string

	dialStopChan       chan struct{}
	dialTimeStart      time.Time
	dialAudioBytesSent uint
	dialVideoBytesSent uint
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

func (n *node) GetVoteData(voteId string) map[string]bool {
	v, _ := n.peerCord.votes.get(voteId)
	return v.Decisions.copy()
}

func (n *node) GetVoteString(voteId string) string {
	v, _ := n.peerCord.votes.get(voteId)
	return fmt.Sprintf("%v node %v", types.VoteTypes[v.VoteType].Name, v.Target)
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
			dialStopChan:    make(chan struct{}, 1),
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

func (n *node) DialInvitePeer(peer string) error {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	if n.peerCord.currentDial.dialState != types.InCall || !n.IsLeader() {
		return fmt.Errorf("peer cannot invite another peer. Not a leader of an existing call")
	}

	// Check that we have a PK for the peer. If not, request it
	_, exists := n.GetPeerKey(peer)
	if !exists {
		n.RequestPK(peer)
	}

	memberList := getMapKeys(n.peerCord.members.copy())

	dialMsg := types.DialMsg{
		CallId:  n.peerCord.currentDial.ID,
		Caller:  n.GetAddress(),
		PubId:   n.crypto.PublicID,
		Members: memberList,
	}

	transpMsg, err := n.conf.MessageRegistry.MarshalMessage(dialMsg)
	if err != nil {
		return err
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
		if <-msgSent {
			to := time.After(10 * time.Second)

			select {
			case <-n.peerCord.currentDial.ResponseChannel:
			case <-to:
			}
		}

		n.peerCord.currentDial.Lock()
		defer n.peerCord.currentDial.Unlock()

		n.peerCord.currentDial.ResponseChannel = newResponseChannel()
	}()

	// We have sucessfully dialed another user
	n.peerCord.currentDial.Peer = peer

	return nil
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
	// trust, err := n.GetTrust(dialMsg.Caller)
	// if err != nil {
	// 	return fmt.Errorf("Failed to get trust from user")
	// }
	trust := 0.0
	accepted := n.gui.PromptDial(dialMsg.Caller, trust, 10*time.Second, dialMsg.CallId, dialMsg.Members...)

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
	n.peerCord.currentDial.ID = dialMsg.CallId

	// Initialize the call members.
	// If it is a group call, the members list will be updated in key exchange
	n.peerCord.members.set(dialMsg.Caller, struct{}{})

	n.peerCord.currentDial.leader = dialMsg.Caller
	n.peerCord.currentDial.dialStopChan = make(chan struct{}, 1)
	n.peerCord.currentDial.dialTimeStart = time.Now()
	go func(stopChan chan struct{}, peer string) {
		for {
			time.Sleep(time.Millisecond * 100)
			select {
			case <-stopChan:
				return
			default:
				callMsg := n.GetNextCallDataMessage()
				data, err := json.Marshal(&callMsg)
				if err != nil {
					n.logger.Err(err).Msg("error when marshaling next 1t1 call data")
				} else {
					transportMsg := transport.Message{Payload: data, Type: callMsg.Name()}
					encryptedMsg, err := n.EncryptOneToOneMsg(&transportMsg, peer)
					if err != nil {
						n.logger.Err(err).Msg("error when encrypting next 1t1 call msg")
					} else {
						err = n.Unicast(peer, *encryptedMsg)
						if err != nil {
							n.logger.Err(err).Msg("error when encrypting next 1t1 call msg")
						} else {
							n.peerCord.currentDial.Lock()
							n.peerCord.currentDial.dialVideoBytesSent += uint(len(callMsg.VideoBytes))
							n.peerCord.currentDial.dialAudioBytesSent += uint(len(callMsg.AudioBytes))
							n.peerCord.currentDial.Unlock()
						}
					}
				}
			}
		}
	}(n.peerCord.currentDial.dialStopChan, dialMsg.Caller)

	return nil
}

func (n *node) ReceiveDialResponse(msg types.Message, packet transport.Packet) error {
	dialResponseMsg, ok := msg.(*types.DialResponseMsg)
	if !ok {
		panic("not a dial response message")
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

		if n.peerCord.currentDial.dialState == types.Dialing {
			// We failed to enter a call
			n.peerCord.currentDial.dialState = types.Idle
		}

		return nil
	}

	// If we made it here, our currentDial is accepted
	n.peerCord.currentDial.ResponseChannel <- true
	fmt.Println("Our call was accepted")

	if n.peerCord.currentDial.dialState == types.Dialing {
		// We were dialing to create a call
		n.peerCord.currentDial.dialState = types.InCall
		n.peerCord.members.set(n.peerCord.currentDial.Peer, struct{}{})
		n.peerCord.currentDial.leader = n.GetAddress()
		n.peerCord.currentDial.dialStopChan = make(chan struct{}, 1)
		n.peerCord.currentDial.dialTimeStart = time.Now()
		go func(stopChan chan struct{}, peer string) {
			for {
				time.Sleep(time.Millisecond * 100)
				select {
				case <-stopChan:
					return
				default:
					callMsg := n.GetNextCallDataMessage()
					data, err := json.Marshal(&callMsg)
					if err != nil {
						n.logger.Err(err).Msg("error when marshaling next 1t1 call data")
					} else {
						transportMsg := transport.Message{Payload: data, Type: callMsg.Name()}
						encryptedMsg, err := n.EncryptOneToOneMsg(&transportMsg, peer)
						if err != nil {
							n.logger.Err(err).Msg("error when encrypting next 1t1 call msg")
						} else {
							err = n.Unicast(peer, *encryptedMsg)
							if err != nil {
								n.logger.Err(err).Msg("error when encrypting next 1t1 call msg")
							} else {
								n.peerCord.currentDial.Lock()
								n.peerCord.currentDial.dialVideoBytesSent += uint(len(callMsg.VideoBytes))
								n.peerCord.currentDial.dialAudioBytesSent += uint(len(callMsg.AudioBytes))
								n.peerCord.currentDial.Unlock()
							}
						}
					}
				}
			}
		}(n.peerCord.currentDial.dialStopChan, n.peerCord.currentDial.Peer)
	} else {
		// This is a result of a group call add.
		n.peerCord.members.set(n.peerCord.currentDial.Peer, struct{}{})

		fmt.Println("Starting key exchange")

		err := n.StartDHKeyExchange(n.peerCord.members.copy())
		if err != nil {
			return err
		}
		multicastGRP := n.NewMulticastGroup()
		n.peerCord.currentDial.multicastGroupID = multicastGRP
		groupExistenceMsg := types.MulticastGroupExistence{GroupSender: n.GetAddress(), GroupID: multicastGRP}
		data, err := json.Marshal(&groupExistenceMsg)
		if err != nil {
			return xerrors.Errorf("error in DH Shared secret Multicast grp existence marshaling: %v", err)
		}
		transportExistenceMsg := transport.Message{Type: groupExistenceMsg.Name(), Payload: data}
		n.NaiveMulticast(transportExistenceMsg, n.peerCord.members.copy())
		n.peerCord.currentDial.dialStopChan <- struct{}{}
		close(n.peerCord.currentDial.dialStopChan)
		n.peerCord.currentDial.dialStopChan = make(chan struct{}, 1)
		n.peerCord.currentDial.dialTimeStart = time.Now()
		go func(stopChan chan struct{}) {
			for {
				time.Sleep(time.Millisecond * 100)
				select {
				case <-stopChan:
					return
				default:
					callMsg := n.GetNextCallDataMessage()
					data, err := json.Marshal(&callMsg)
					if err != nil {
						n.logger.Err(err).Msg("error when marshaling next call data")
					} else {
						transportMsg := transport.Message{Payload: data, Type: callMsg.Name()}
						encryptedMsg, err := n.EncryptDHMsg(&transportMsg)
						if err != nil {
							n.logger.Err(err).Msg("error when encrypting next call msg")
						} else {
							err = n.Multicast(*encryptedMsg, n.peerCord.currentDial.multicastGroupID)
							if err != nil {
								n.logger.Err(err).Msg("error when encrypting next call msg")
							} else {
								n.peerCord.currentDial.Lock()
								n.peerCord.currentDial.dialVideoBytesSent += uint(len(callMsg.VideoBytes))
								n.peerCord.currentDial.dialAudioBytesSent += uint(len(callMsg.AudioBytes))
								n.peerCord.currentDial.Unlock()
							}
						}
					}
				}
			}
		}(n.peerCord.currentDial.dialStopChan)
	}

	return nil
}

func (n *node) EndCall() {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()

	if n.peerCord.currentDial.dialState == types.InCall {
		hangUp := types.HangUpMsg{
			Member: n.GetAddress(),
			CallId: n.peerCord.currentDial.ID,
		}

		marshaledMsg, err := n.conf.MessageRegistry.MarshalMessage(hangUp)
		if err == nil {
			err = n.SendToCall(&marshaledMsg)
			if err != nil {
				n.logger.Err(err).Msg("error when sending hang up msg")
			}
		}

		if n.guiReady() {
			rating := n.gui.PromptRating("Please rate your experience with this call based on the peer who called you. Options: {2 = good, 1 = bad}")
			originPeer := n.peerCord.currentDial.leader

			n.EigenRatePeer(originPeer, rating-2)
		}
	}

	n.peerCord.members = newSafeMap[string, struct{}]()
	n.peerCord.currentDial.ResponseChannel = newResponseChannel()

	n.peerCord.currentDial.dialState = types.Idle
	n.peerCord.currentDial.ID = ""

	n.peerCord.currentDial.dialAudioBytesSent = 0
	n.peerCord.currentDial.dialVideoBytesSent = 0
	n.peerCord.currentDial.dialStopChan <- struct{}{}
	close(n.peerCord.currentDial.dialStopChan)
	n.peerCord.currentDial.dialStopChan = make(chan struct{}, 1)

}

func (n *node) receiveHangUp(msg types.Message, packet transport.Packet) error {
	hangUpMsg, ok := msg.(*types.HangUpMsg)
	if !ok {
		panic("not a hang up message")
	}

	n.peerCord.currentDial.Lock()

	if n.peerCord.currentDial.dialState == types.Idle || hangUpMsg.CallId != n.peerCord.currentDial.ID {
		n.peerCord.currentDial.Unlock()
		return fmt.Errorf("received hang up message not for me")
	}

	isLeader := n.IsLeader()
	n.peerCord.currentDial.Unlock()

	if isLeader {
		// One of our members left. We need to remove them from the call
		n.peerCord.members.delete(hangUpMsg.Member)
		if n.peerCord.members.len() == 0 {
			// Our call is over. End the call.
			go n.EndCall()
		} else if n.peerCord.members.len() > 1 {
			// We are still in a group call so we have to regenerate the keys
			n.GroupCallRemove(hangUpMsg.Member)
		}
	} else {
		if n.peerCord.currentDial.leader == hangUpMsg.Member {
			// The leader left the call. We need to hang up
			go n.EndCall()
		}
	}

	return nil
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

func (n *node) SendToCall(msg *transport.Message) error {
	var encryptedMsg *transport.Message
	var err error

	// Encrypt
	if n.peerCord.members.len() > 1 {
		encryptedMsg, err = n.EncryptDHMsg(msg)
	} else {
		// We are in a 1 to 1 encryption method
		for k := range n.peerCord.members.copy() {
			encryptedMsg, err = n.EncryptOneToOneMsg(msg, k)
		}
	}

	if err != nil {
		return err
	}

	// TODO: Replace with a multicast group
	n.logger.Warn().Msgf("Sending to group msg of type %v", msg.Type)
	for member := range n.peerCord.members.copy() {
		go n.Unicast(member, *encryptedMsg)
	}
	return nil
}

func (n *node) IsLeader() bool {
	return n.peerCord.currentDial.leader == n.GetAddress()
}

func (n *node) GetAudioThroughput() float64 {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()
	return float64(n.peerCord.currentDial.dialAudioBytesSent) / float64(time.Since(n.peerCord.currentDial.dialTimeStart))
}

func (n *node) GetVideoThroughput() float64 {
	n.peerCord.currentDial.Lock()
	defer n.peerCord.currentDial.Unlock()
	return float64(n.peerCord.currentDial.dialVideoBytesSent) / float64(time.Since(n.peerCord.currentDial.dialTimeStart))
}
