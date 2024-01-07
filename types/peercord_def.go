package types

/** Call Dialing **/
type DialState int

const (
	Idle DialState = iota
	Dialing
	InCall
)

// TODO: Need to send a dial message at the end of a vote with a list of existing members
type DialMsg struct {
	CallId         string
	Caller         string
	PubId          string
	PublicKeyBytes []byte
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
