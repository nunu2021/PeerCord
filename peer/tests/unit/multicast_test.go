package unit

import (
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
	"testing"
	"time"
)

func Test_NaiveMulticast(t *testing.T) {
	transp := channel.NewTransport()

	fake := z.NewFakeMessage(t)

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node.Stop()

	sock1, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock1.Close()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	sock3, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock3.Close()

	node.AddPeer(sock1.GetAddress())
	node.AddPeer(sock2.GetAddress())
	node.AddPeer(sock3.GetAddress())

	recipients := make(map[string]struct{})
	recipients[sock1.GetAddress()] = struct{}{}
	recipients[sock3.GetAddress()] = struct{}{}

	err = node.NaiveMulticast(fake.GetNetMsg(t), recipients)
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 800)

	// will fill the getIns
	sock1.Recv(time.Millisecond * 10)
	sock2.Recv(time.Millisecond * 10)

	// to be sure there isn't additional messages
	sock1.Recv(time.Millisecond * 10)
	sock2.Recv(time.Millisecond * 10)
	sock3.Recv(time.Millisecond * 10)

	// > the node should have received no message
	n1Ins := node.GetIns()
	require.Len(t, n1Ins, 0)

	// > the node should have sent two messages: one for sock1, one for sock3
	outs := node.GetOuts()
	require.Len(t, outs, 2)
	require.Equal(t, outs[0].Header.Destination, sock1.GetAddress())
	require.Equal(t, outs[1].Header.Destination, sock3.GetAddress())
}
