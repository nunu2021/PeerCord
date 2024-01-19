package main

import (
	"fmt"
	"os"
	"regexp"

	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport/udp"
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

func SanitizePID(pubID string) bool {
	if len(pubID) != 12 {
		return false
	}
	match, _ := regexp.Match("[+]{1}[0-9]{11}", []byte(pubID))
	return match
}

func main() {
	node := z.NewTestNode(t, impl.NewPeer, udp.NewUDP(), "127.0.0.1:0")
	pubID := ""
	if len(os.Args) > 2 && SanitizePID(os.Args[2]) {
		node.SetPublicID(os.Args[2])
		pubID = os.Args[2]
	} else {
		fmt.Println("no pubID")
		return
	}
	gui := impl.NewPeercordGUI(&node)

	fmt.Println(fmt.Sprintf("Opening node on socket: %v", node.GetAddr()))

	gui.Show(node.GetAddr(), pubID)
}
