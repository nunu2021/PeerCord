package types

import "time"

/** GUI **/

type PeercordGUI interface {

	// Creates and shows the gui. This is a blocking call
	Show() error

	// Blocking call to ask the user if they would like to pick up a dial
	PromptDial(peer string, trust float64, dialTimeout time.Duration) bool

	// Blocking call to prompt user for boolen choice between A and B.
	//
	// Returns
	//   true -> A
	//   false -> B
	PromptBinaryChoice(a, b string) bool

	// Blocking call to prompt user to rate the quality of a call with the prompt string "prompt"
	// Returns an integer [1, 5]
	PromptRating(prompt string) int
}

/** Call Dialing **/
type DialState int

const (
	Idle DialState = iota
	Dialing
	InCall
)

type PKRequestMessage struct {
	PeerId      string
	PubId       string
	PubKeyBytes []byte
}

type PKResponseMessage struct {
	PeerId      string
	PubId       string
	PubKeyBytes []byte
}

// TODO: Need to send a dial message at the end of a vote with a list of existing members
type DialMsg struct {
	CallId  string
	Caller  string
	PubId   string
	Members []string
}

/** Voting **/

type VoteType int

type GroupCallVotePkt struct {
	Voter    string
	ID       string
	Type     VoteType
	Decision bool
	Meta     string
}

type VoteData struct {
	Name      string
	Threshold float32
}

const (
	GroupAdd VoteType = iota
	GroupKick
)

var VoteTypes = []VoteData{
	{
		Name:      "groupAdd",
		Threshold: 0.5,
	},
	{
		Name:      "groupKick",
		Threshold: 0.5,
	},
}
