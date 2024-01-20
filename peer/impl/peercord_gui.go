package impl

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

type GUIVoteData struct {
	method string
	target string
	agree  int
	reject int
}

type PeercordGUI struct {
	types.PeercordGUI

	peer peer.Peer

	app        fyne.App
	mainWindow fyne.Window

	memberList    []string
	selectedIndex int
	typedPeer     string

	currentVote string

	callIdLabel *widget.Label
}

func NewPeercordGUI(peer peer.Peer) PeercordGUI {
	return PeercordGUI{
		peer: peer,

		selectedIndex: -1,
		currentVote:   "",
	}
}

func containerRoutingSetup(node peer.Peer) *fyne.Container {

	peer := ""
	relay := ""

	peerInput := widget.NewEntry()
	peerInput.SetPlaceHolder("Peer address")
	peerInput.OnChanged = func(s string) { peer = s }

	relayInput := widget.NewEntry()
	relayInput.SetPlaceHolder("Relay address")
	relayInput.OnChanged = func(s string) { relay = s }

	addButton := widget.NewButton("Add to Routing", func() { handleRoutingSetup(node, peer, relay) })

	return container.NewVBox(
		container.NewBorder(
			nil,
			nil,
			widget.NewLabel("Peer:"),
			nil,
			peerInput,
		),
		container.NewBorder(
			nil,
			nil,
			widget.NewLabel("Relay:"),
			nil,
			relayInput,
		),
		addButton,
	)
}

func (gui *PeercordGUI) containerVoteData() *fyne.Container {

	actionLabel := widget.NewLabel("")
	totalLabel := widget.NewLabel("")
	agreeLabel := widget.NewLabel("")
	rejectLabel := widget.NewLabel("")

	// Vote Data Updater
	go func() {
		for range time.Tick(time.Millisecond * 100) {
			if gui.currentVote != "" {
				votes := gui.peer.GetVoteData(gui.currentVote)
				voteString := gui.peer.GetVoteString(gui.currentVote)

				accept := 0
				reject := 0
				total := 0

				for _, decision := range votes {
					total++
					if decision {
						accept++
					} else {
						reject++
					}
				}

				totalLabel.SetText(fmt.Sprintf("(%v Nodes)", total))
				agreeLabel.SetText(fmt.Sprint(accept))
				rejectLabel.SetText(fmt.Sprint(reject))

				actionLabel.SetText(fmt.Sprintf(voteString))

			} else {
				totalLabel.SetText("")
				agreeLabel.SetText("")
				rejectLabel.SetText("")

				actionLabel.SetText("")
			}
		}
	}()

	return container.NewVBox(
		container.NewHBox(
			widget.NewLabel("Current Vote:"),
			actionLabel,
			totalLabel,
		),
		container.NewBorder(
			nil,
			nil,
			container.NewHBox(
				widget.NewLabel("Agree - "),
				agreeLabel,
			),
			container.NewHBox(
				widget.NewLabel("Reject - "),
				rejectLabel,
			),
		),
	)
}

func (gui *PeercordGUI) Show(addr, pubID string) {
	gui.peer.SetGui(gui)

	gui.app = app.New()
	gui.mainWindow = gui.app.NewWindow("Peercord UI")

	// My IP Indicater
	myIp := container.NewHBox(
		widget.NewLabel("My IP:"),
		widget.NewLabel(addr),
	)

	// My pubID Indicater
	myID := container.NewHBox(
		widget.NewLabel("My ID:"),
		widget.NewLabel(pubID),
	)

	// Call Status
	callStatusLabel := widget.NewLabel("")
	callStatus := container.NewHBox(
		widget.NewLabel("Call status:"),
		callStatusLabel,
		widget.NewButton("Leave call", func() {
			handleLeaveCall(gui.peer)
		}),
	)

	// Call ID: ______
	gui.callIdLabel = widget.NewLabel("")
	callId := container.NewHBox(
		widget.NewLabel("Call ID:"),
		gui.callIdLabel,
	)

	// Peer Address Input
	peerAddressInput := widget.NewEntry()
	peerAddressInput.SetPlaceHolder("Peer address")
	peerAddressInput.OnChanged = func(s string) { gui.typedPeer = s }

	// Dial a Peer
	dialButton := widget.NewButton("Dial Peer", func() {
		callId := handleDial(gui.peer, gui.typedPeer, gui.mainWindow.Canvas())
		gui.callIdLabel.SetText(callId)
	})

	// Vote to add
	groupAdd := widget.NewButton("Vote Add Peer", func() {
		typedPeer := gui.getTypedPeer()

		if typedPeer != "" {
			gui.handleVoteAdd(gui.peer, typedPeer)
		}
	})

	// Kick from Group
	groupKick := widget.NewButton("Vote kick member", func() {
		selectedRemote := gui.getSelecedRemote()

		if selectedRemote != "" {
			handleVoteKick(gui.peer, selectedRemote)
		}
	})

	// Group Call Members
	groupCallData := binding.BindStringList(&gui.memberList)

	remotesList := widget.NewListWithData(
		groupCallData,
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(item binding.DataItem, obj fyne.CanvasObject) {
			obj.(*widget.Label).Bind(item.(binding.String))
		},
	)

	// Set click handler
	remotesList.OnSelected = func(id widget.ListItemID) {
		gui.selectedIndex = id
	}

	// Full window Content
	content := container.NewBorder(
		container.NewVBox(
			containerRoutingSetup(gui.peer),
			myIp,
			myID,
			callStatus,
			callId,
			peerAddressInput,
			dialButton,
			gui.containerVoteData(),
			groupAdd,
			groupKick,
		),
		nil,
		nil,
		nil,
		remotesList,
	)

	// Call Status Updater
	go func() {
		for range time.Tick(time.Millisecond * 100) {
			callStatusLabel.SetText(getDialStateString(gui.peer))
		}
	}()

	// Member List Updater
	go func() {
		for range time.Tick(time.Millisecond * 100) {
			// Update member list
			gui.memberList = getMapKeys(gui.peer.GetGroupCallMembers())

			err := groupCallData.Reload()
			if err != nil {
				log.Warn().Err(err).Msg("failed to refresh group call data")
				return
			}
		}
	}()

	// TEST: Update group member list. Make sure to comment (gui.memberList =) above
	// go func() {
	// 	for {
	// 		time.Sleep(time.Second * 3)
	// 		gui.memberList = []string{"127.0.0.1"}
	// 		time.Sleep(time.Second * 3)
	// 		gui.memberList = []string{"127.0.0.1", "127.0.0.2"}
	// 		time.Sleep(time.Second * 3)
	// 		gui.memberList = []string{"127.0.0.3", "127.0.0.2"}
	// 	}
	// }()

	// TEST: Run and print prompt
	// go func() {
	// 	time.Sleep(time.Second * 2)
	// 	fmt.Println(gui.PromptDial("127.0.0.1", 3674.123, 8*time.Second))
	// }()

	gui.mainWindow.SetContent(content)
	gui.mainWindow.Resize(fyne.NewSize(500, 700))
	gui.mainWindow.ShowAndRun() // Blocking
}

func (gui *PeercordGUI) getSelecedRemote() string {
	if gui.selectedIndex == -1 {
		return ""
	}

	return gui.memberList[gui.selectedIndex]
}

func (gui *PeercordGUI) getTypedPeer() string {
	return gui.typedPeer
}

func getMapKeys[M ~map[K]V, K comparable, V any](m M) []K {
	r := make([]K, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
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

/**** BUTTON HANDLERS *****/

// handleRoutingSetup add a peer to the routing table via the specified relay
func handleRoutingSetup(node peer.Peer, peer, relay string) {
	node.SetRoutingEntry(peer, relay)
	fmt.Println(fmt.Sprintf("Adding %v through %v", peer, relay))
}

// handleDial dials the peer at the specified address, then returns the call id
func handleDial(node peer.Peer, address string, canvas fyne.Canvas) string {
	callId, err := node.DialPeer(address)
	if err != nil {
		log.Err(err).Msgf("failed to dial peer %s", address)
		return ""
	}

	var popUp *widget.PopUp

	popUp = widget.NewModalPopUp(
		container.NewVBox(
			widget.NewLabel(fmt.Sprintf("Dialing %v...", address)),
			widget.NewButton("Cancel", func() {
				node.EndCall()
				popUp.Hide()
			}),
		),
		canvas,
	)

	go func() {
		for range time.Tick(time.Millisecond * 100) {
			if node.CallLineState() != types.Dialing {
				popUp.Hide()
			}
		}
	}()

	popUp.Show()

	return callId
}

// handleLeaveCall leaves the current call if not idling.
func handleLeaveCall(node peer.Peer) {
	if node.CallLineState() != types.Idle {
		node.EndCall()
	}
}

// handleVoteKick initiates a vote-add round for the member specified by address
func (gui *PeercordGUI) handleVoteAdd(node peer.Peer, address string) {
	gui.currentVote, _ = node.StartVote(types.GroupAdd, true, address)
}

// handleVoteKick initiates a vote-kicking round for the member specified by address
func handleVoteKick(node peer.Peer, address string) {
	fmt.Printf("Address %v\n", address)
}

/***** PROMPTS *****/

// TODO: Change last element to strint pair
func (gui *PeercordGUI) PromptDial(peer string, trust float64, dialTimeoutSec time.Duration, callId string, members ...string) bool {

	retVal := make(chan bool)

	var popUp *widget.PopUp

	hangUp := widget.NewButton("Hang Up", func() {
		retVal <- false
		popUp.Hide()
	})

	pickUp := widget.NewButton("Pick Up", func() {
		retVal <- true
		popUp.Hide()
	})

	members = append(members, peer)

	popUp = widget.NewModalPopUp(
		container.NewVBox(
			widget.NewLabel(fmt.Sprintf("Incoming call from %v. Pick up?", strings.Join(members, ", "))),
			widget.NewLabel(fmt.Sprintf("%v trust: %v", peer, trust)), // TODO: Get trust for all the members
			container.NewHBox(
				hangUp,
				pickUp,
			),
		),
		gui.mainWindow.Canvas(),
	)

	popUp.Show()

	result := false
	to := time.After(dialTimeoutSec)

	select {
	case <-to:
		popUp.Hide()
	case result = <-retVal:
	}

	if result == true {
		gui.callIdLabel.SetText(callId)
	}

	return result
}

// Blocking call to ask the user if they would like to vote in agreement
func (gui *PeercordGUI) PromptVote(votePrompt string, voteTimeout time.Duration) bool {
	retVal := make(chan bool)

	var popUp *widget.PopUp

	reject := widget.NewButton("Reject", func() {
		retVal <- false
		popUp.Hide()
	})

	accept := widget.NewButton("Accept", func() {
		retVal <- true
		popUp.Hide()
	})

	popUp = widget.NewModalPopUp(
		container.NewVBox(
			widget.NewLabel(votePrompt),
			container.NewHBox(
				reject,
				accept,
			),
		),
		gui.mainWindow.Canvas(),
	)

	popUp.Show()

	result := false
	to := time.After(voteTimeout)

	select {
	case <-to:
		popUp.Hide()
	case result = <-retVal:
	}

	return result
}

func (gui *PeercordGUI) PromptBinaryChoice(a, b string) bool {

	selected := true
	retVal := make(chan bool)

	var popUp *widget.PopUp

	button := widget.NewButton("Enter", func() {
		retVal <- selected
		popUp.Hide()
	})
	button.Disable()

	popUp = widget.NewModalPopUp(
		container.NewVBox(
			widget.NewLabel("Please select an option: "),
			widget.NewSelect([]string{a, b}, func(s string) {
				selected = (a == s)
				button.Enable()
			}),
			button,
		),
		gui.mainWindow.Canvas(),
	)

	popUp.Show()

	return <-retVal
}

func (gui *PeercordGUI) PromptRating(prompt string) int {

	selected := binding.NewInt()
	selected.Set(0)

	retVal := make(chan int)

	var popUp *widget.PopUp

	button := widget.NewButton("Enter", func() {
		v, _ := selected.Get()
		retVal <- v
		popUp.Hide()
	})
	button.Disable()

	starSize := fyne.Size{
		Width:  50,
		Height: 50,
	}

	empty := "peer/impl/assets/empty_star.png"
	filled := "peer/impl/assets/filled_star.png"

	newStar := func(index int) *canvas.Image {
		star := canvas.NewImageFromFile(empty)

		selected.AddListener(binding.NewDataListener(func() {
			val, err := selected.Get()

			if err != nil {
				log.Err(err).Msgf("failed to get selected val")
				return
			}

			if val >= index {
				star.File = filled
			} else {
				star.File = empty
			}

			star.Refresh()
		}))

		star.FillMode = canvas.ImageFillContain
		star.SetMinSize(starSize)

		return star
	}

	popUp = widget.NewModalPopUp(
		container.NewVBox(
			widget.NewLabel("Please select an option: "),
			container.NewHBox(
				widget.NewButton("-", func() {
					val, err := selected.Get()
					if err == nil {
						if val > 1 {
							selected.Set(val - 1)
						}
					}
				}),
				newStar(1),
				newStar(2),
				newStar(3),
				newStar(4),
				newStar(5),
				widget.NewButton("+", func() {
					val, err := selected.Get()
					if err == nil {
						if val < 5 {
							selected.Set(val + 1)
						}
					}
				}),
			),
			button,
		),
		gui.mainWindow.Canvas(),
	)

	popUp.Show()

	selected.AddListener(binding.NewDataListener(func() {
		val, err := selected.Get()
		if err == nil && 1 <= val && val <= 5 {
			button.Enable()
		}
	}))

	return <-retVal
}
