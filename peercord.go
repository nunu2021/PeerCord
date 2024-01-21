package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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

func main() {

	fmt.Print("This is the Nth peer in the system. Input N:")
	reader := bufio.NewReader(os.Stdin)
	// ReadString will block until the delimiter is entered
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("An error occured while reading input. Please try again", err)
		return
	}

	// remove the delimeter from the string
	input = strings.TrimSuffix(input, "\n")
	ttlPeers, err := strconv.Atoi(input)
	if err != nil || ttlPeers < 0 {
		fmt.Println("Please input a positive number. Try Again.", err)
	}
	fmt.Print("Please copy the address fo the bootstrap node here:")
	input, err = reader.ReadString('\n')
	if err != nil {
		fmt.Println("An error occured while reading input. Please try again", err)
		return
	}

	transp := udp.NewUDP()
	node := z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0",
		z.WithAntiEntropy(time.Millisecond*500),
		z.WithContinueMongering(1),
		z.WithHeartbeat(time.Hour*24),
		z.WithStartTrust(),
		z.WithBootstrapAddrs([]string{input}),
		z.WithTotalPeers(uint(ttlPeers)),
	)

	gui := impl.NewPeercordGUI(&node)

	fmt.Println(fmt.Sprintf("Opening node on socket: %v", node.GetAddr()))

	gui.Show(node.GetAddr(), node.GetPubId(), node.GetAudioThroughput(), node.GetVideoThroughput())

	node.Stop()
}
