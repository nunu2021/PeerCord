package impl

import (
	"fmt"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type VoteData struct {
	complete  bool
	VoteType  types.VoteType
	Target    string
	Decisions safeMap[string, bool]
}

func newVoteData(voteType types.VoteType, target string) VoteData {
	return VoteData{
		VoteType:  voteType,
		Target:    target,
		Decisions: newSafeMap[string, bool](),
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
		Proposer: n.GetAddress(),
	}

	// Store this vote as a "seen" vote
	n.peerCord.votes.set(voteId, newVoteData(voteType, voteMeta))
	vd, _ := n.peerCord.votes.get(voteId)
	vd.Decisions.set(n.GetAddress(), voteDecision)

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
		n.peerCord.votes.set(vote.ID, newVoteData(vote.Type, vote.Meta))
	}

	// Store the peer's result in the results group. If we've received a message from them before, we ignore the new
	voteData, _ := n.peerCord.votes.get(vote.ID)
	_, peerVoted := voteData.Decisions.get(vote.Voter)
	if !peerVoted {
		// New vote
		voteData.Decisions.set(vote.Voter, vote.Decision)
	} else if voted {
		// If the peer had already voted and we have already voted, nothing changed. Return to optimize
		return
	}

	// Check if we need to vote. If yes, do so
	if !voted {
		// Make a vote decision
		myDecision := n.GroupVoteDecision(vote.Type, vote.Proposer, vote.Meta)

		myVote := types.GroupCallVotePkt{
			Voter:    n.GetAddress(),
			ID:       vote.ID,
			Type:     vote.Type,
			Decision: myDecision,
			Meta:     vote.Meta,
			Proposer: vote.Proposer,
		}

		// If we failed to send the vote, ignore for now.
		err := n.SendGroupVote(myVote)
		if err != nil {
			n.logger.Err(err).Msgf("Unable to cast vote")
		}

		n.gui.RegisterCurrentVote(vote.ID)
	}

	// Check for a consensus
	nAgreers := 0
	{
		votes := voteData.Decisions.internalMap()

		for _, decision := range votes {
			if decision {
				nAgreers++
			}
		}

		voteData.Decisions.unlock()
	}

	if float32(nAgreers)/float32(n.peerCord.members.len()+1) > types.VoteTypes[vote.Type].Threshold {
		// The vote has reached a consensus
		voteData.complete = true
		n.CompleteVoteAction(vote.Type, vote.Meta)
	}

}

func (n *node) GroupVoteDecision(voteType types.VoteType, proposer, voteMeta string) bool {
	// Make Decision
	if n.guiReady() == false {
		return false
	}

	voteDecision := n.gui.PromptVote(fmt.Sprintf(types.VoteTypes[voteType].Prompt, proposer, voteMeta), time.Second*8)

	return voteDecision
}

func (n *node) SendGroupVote(myVote types.GroupCallVotePkt) error {
	// Package the vote into a transport packet
	marshaledMsg, err := n.conf.MessageRegistry.MarshalMessage(myVote)
	if err != nil {
		return err
	}

	return n.SendToCall(&marshaledMsg)
}

func (n *node) CompleteVoteAction(voteType types.VoteType, voteMeta string) {
	switch voteType {
	case types.GroupAdd:
		// If we are the leader, we have to initiate key exchanges

		if n.IsLeader() {
			err := n.DialInvitePeer(voteMeta)
			if err != nil {
				n.logger.Err(err)
			}
		}
	case types.GroupKick:
		// If we are the leader, we have to initiate key exchanges
		if n.IsLeader() {
			hangUp := types.HangUpMsg{
				Member: n.GetAddress(),
				CallId: n.peerCord.currentDial.ID,
			}

			marshaledMsg, err := n.conf.MessageRegistry.MarshalMessage(hangUp)
			if err == nil {
				err = n.Unicast(voteMeta, marshaledMsg)
				if err != nil {
					n.logger.Err(err).Msg("error when sending hang up msg")
				}
			}

			if n.peerCord.members.len() == 2 {
				// We are entering individual calls again. TODO: Make sure we the other users PK
			} else {
				err := n.GroupCallRemove(voteMeta)
				if err != nil {
					n.logger.Err(err).Msg("error when reinitializing group key")
				}
			}
		}
	}
}
