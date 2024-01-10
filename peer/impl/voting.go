package impl

import (
	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type VoteData struct {
	complete  bool
	decisions safeMap[string, bool]
}

func newVoteData() VoteData {
	return VoteData{
		decisions: newSafeMap[string, bool](),
	}
}

// Start a vote of any type. Returns the vote ID of the initiated vote
func (n *node) StartVote(voteType types.VoteType, voteDecision bool, voteMeta string) (string, error) {
	voteId := xid.New().String()

	myVote := types.GroupCallVotePkt{
		Voter:    n.GetAddress(),
		ID:       voteId,
		Type:     voteType,
		Decision: voteDecision,
		Meta:     voteMeta,
	}

	// Store this vote as a "seen" vote
	n.peerCord.votes.set(voteId, newVoteData())

	return voteId, n.SendGroupVote(myVote)
}

func (n *node) ReceiveGroupCallVotePktMsg(msg types.Message, packet transport.Packet) error {
	groupCallVotePkt, ok := msg.(*types.GroupCallVotePkt)
	if !ok {
		panic("not a status message")
	}

	n.ProcessVote(*groupCallVotePkt)

	return nil
}

// Callback for processing a vote for a specific vote
// TODO: We need to clean up old votes and include a timeout maybe?
func (n *node) ProcessVote(vote types.GroupCallVotePkt) {

	// Check if we have seen this vote before.
	//   If yes, check if the vote is already completed
	//   If not, set up vote data and flag for casting own vote later
	oldVoteData, voted := n.peerCord.votes.get(vote.ID)
	if voted {
		if oldVoteData.complete {
			return
		}
	} else {
		n.peerCord.votes.set(vote.ID, newVoteData())
	}

	// Store the peer's result in the results group. If we've received a message from them before, we ignore the new
	voteData, _ := n.peerCord.votes.get(vote.ID)
	_, peerVoted := voteData.decisions.get(vote.Voter)
	if !peerVoted {
		// New vote
		voteData.decisions.set(vote.Voter, vote.Decision)
	} else if voted {
		// If the peer had already voted and we have already voted, nothing changed. Return to optimize
		return
	}

	// Check if we need to vote. If yes, do so
	if !voted {
		// Make a vote decision
		myDecision := n.GroupVoteDecision(vote.Type, vote.Meta)

		myVote := types.GroupCallVotePkt{
			Voter:    n.GetAddress(),
			ID:       vote.ID,
			Type:     vote.Type,
			Decision: myDecision,
			Meta:     vote.Meta,
		}

		// If we failed to send the vote, ignore for now.
		_ = n.SendGroupVote(myVote)
	}

	// Check for a consensus
	nAgreers := 0
	{
		votes := voteData.decisions.internalMap()

		for _, decision := range votes {
			if decision {
				// TODO: Weight decisions based on users trust
				nAgreers++
			}
		}

		voteData.decisions.unlock()
	}

	if float32(nAgreers)/float32(n.peerCord.members.len()) > types.VoteTypes[vote.Type].Threshold {
		// The vote has reached a consensus
		voteData.complete = true
		n.CompleteVoteAction(vote.Type, vote.Meta)
	}

}

func (n *node) GroupVoteDecision(voteType types.VoteType, voteMeta string) bool {
	// Make Decision
	voteDecision := true // TODO: Logic for vote decision

	return voteDecision
}

func (n *node) SendGroupVote(myVote types.GroupCallVotePkt) error {
	// Package the vote into a transport packet
	marshaledMsg, err := n.conf.MessageRegistry.MarshalMessage(myVote)
	if err != nil {
		return err
	}

	var encryptedMsg *transport.Message

	// Encrypt
	if n.peerCord.members.len() == 2 {
		// We are in a 1 to 1 encryption method
		encryptedMsg, err = n.EncryptOneToOneMsg(&marshaledMsg, n.peerCord.currentDial.Peer)
	} else {
		encryptedMsg, err = n.EncryptDHMsg(&marshaledMsg)
	}

	if err != nil {
		return err
	}

	// And broadcast TODO: Replace with multicast
	return n.Broadcast(*encryptedMsg)
}

func (n *node) CompleteVoteAction(voteType types.VoteType, voteMeta string) {
	switch voteType {
	case types.GroupAdd:
		n.peerCord.currentDial.Lock()
		defer n.peerCord.currentDial.Unlock()

		n.peerCord.members.set(voteMeta, struct{}{})

		// If we are the leader, we have to initiate key exchanges
		if n.peerCord.currentDial.IsLeader {
			if n.peerCord.members.len() == 2 {
				// We are entering a group call. Initiate DH
				members := n.peerCord.members.internalMap()
				defer n.peerCord.members.unlock()

				err := n.StartDHKeyExchange(members)
				if err != nil {
					// TODO: What if the key exchange failed?
				}
			} else {
				// We are already in a call, run the group call add
				n.GroupCallAdd(voteMeta)
			}
		}
	case types.GroupKick:
		n.peerCord.members.delete(voteMeta)

		// If we are the leader, we have to initiate key exchanges
		if n.peerCord.currentDial.IsLeader {
			if n.peerCord.members.len() == 2 {
				// We are entering individual calls again. TODO: Make sure we the other users PK
			} else {
				n.GroupCallRemove(voteMeta)
			}
		}
	}
}
