package main

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/rs/zerolog/log"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport/udp"
	"go.dedis.ch/cs438/types"
	"os"
	"strconv"
	"time"
)

var t = testing{}

type testing struct{}

func (testing) Errorf(format string, args ...interface{}) {
	fmt.Println("~~ERROR~~")
	fmt.Printf(format, args...)
}
func (testing) FailNow() {
	os.Exit(1)
}

func main() {
	node := z.NewTestNode(t, impl.NewPeer, udp.NewUDP(), "127.0.0.1:0")
	gui := app.New()
	window := gui.NewWindow("Peercord UI")

	// - call status
	callIdLabel := widget.NewLabel("")
	callStatusLabel := widget.NewLabel("None")
	go func() {
		for range time.Tick(time.Millisecond * 500) {
			callStatusLabel.SetText(getDialStateString(node))
		}
	}()

	// - leaving call
	leaveCallButton := widget.NewButton("Leave call", func() {
		handleLeaveCall(node)
	})

	// - list of group call members
	// groupCallData := binding.BindStringList(getMapKeys(node.GetGroupCallMembers()))
	// temporary data for demo purposes
	groupCallData := binding.BindStringList(&[]string{"127.0.0.1:12345", "127.0.0.1:12346"})
	remotesList := widget.NewListWithData(
		groupCallData,
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(item binding.DataItem, obj fyne.CanvasObject) {
			obj.(*widget.Label).Bind(item.(binding.String))
		},
	)

	// - peer operations
	selectedRemote := ""
	remotesList.OnSelected = func(id widget.ListItemID) {
		item, err := groupCallData.GetItem(id)
		if err != nil {
			return
		}

		selectedVal, err := item.(binding.String).Get()
		if err != nil {
			return
		}
		selectedRemote = selectedVal
	}
	kickButton := widget.NewButton("Vote kick member", func() {
		if selectedRemote != "" {
			handleVoteKick(node, selectedRemote)
		}
	})

	// - - - - - - - - - dial a new peer
	peerAddressInput := widget.NewEntry()
	peerAddressInput.SetPlaceHolder("Peer address")
	dialButton := widget.NewButton("Dial", func() {
		callId := handleDial(node.Peer, peerAddressInput.Text)
		err := groupCallData.Reload()
		if err != nil {
			log.Warn().Err(err).Msg("failed to refresh group call data")
			return
		}
		callIdLabel.SetText(callId)
	})

	// window contents
	content := container.NewBorder(
		container.New(
			layout.NewVBoxLayout(),
			container.NewHBox(
				widget.NewLabel("Call status:"),
				callStatusLabel,
				leaveCallButton,
			),
			container.NewHBox(
				widget.NewLabel("Call ID:"),
				callIdLabel,
			),
			widget.NewLabel("Dial peer"),
			peerAddressInput,
			dialButton,
			widget.NewLabel("Group call members:"),
			kickButton,
		),
		nil,
		nil,
		nil,
		remotesList,
	)

	window.SetContent(content)
	window.Resize(fyne.NewSize(500, 500))
	window.ShowAndRun()

	node.Stop()
}

func getMapKeys[M ~map[K]V, K comparable, V any](m M) *[]K {
	r := make([]K, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return &r
}

func getDialStateString(node peer.Peer) string {
	switch state := node.CallLineState(); state {
	case types.Idle:
		return "Idle"
	case types.Dialing:
		return "Dialing"
	case types.InCall:
		return "In call"
	default:
		return "Unknown state: " + strconv.Itoa(int(state))
	}
}

// handleDial dials the peer at the specified address, then returns the call id
func handleDial(node peer.Peer, address string) string {
	callId, err := node.DialPeer(address)
	if err != nil {
		log.Err(err).Msgf("failed to dial peer %s", address)
		return ""
	}
	return callId
}

// handleLeaveCall leaves the current call if not idling.
func handleLeaveCall(node peer.Peer) {
	if node.CallLineState() != types.Idle {
		node.EndCall()
	}
}

// handleVoteKick initiates a vote-kicking round for the member specified by address
func handleVoteKick(node peer.Peer, address string) {
}
