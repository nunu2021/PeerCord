package main

import (
	"fmt"
	"os"
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
	transp := udp.NewUDP()

	bootstrap := z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0", z.WithBootstrap(), z.WithStartTrust())
	node := z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0",
		z.WithAntiEntropy(time.Millisecond*500),
		z.WithContinueMongering(1),
		z.WithHeartbeat(time.Hour*24),
		z.WithStartTrust(),
		z.WithBootstrapAddrs([]string{bootstrap.GetAddr()}),
	)

	gui := impl.NewPeercordGUI(&node)

	fmt.Println(fmt.Sprintf("Opening node on socket: %v", node.GetAddr()))

	gui.Show(node.GetAddr(), node.GetPubId(), node.GetAudioThroughput(), node.GetVideoThroughput())

	node.Stop()
}
