package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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

	bootstrap := z.NewTestNode(t, impl.NewPeer, transp, "127.0.0.1:0", z.WithBootstrap())
	fmt.Println(" the bootstrap node is at address :", bootstrap.GetAddr())

	fmt.Print("Press any key and then [ENTER] to stop the bootstrap node.")
	reader := bufio.NewReader(os.Stdin)
	// ReadString will block until the delimiter is entered
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("An error occured while reading input. Please try again", err)
		return
	}

	// remove the delimeter from the string
	input = strings.TrimSuffix(input, "\n")

	bootstrap.Stop()
}
