package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
)

func TestPeercord_DialAccept(t *testing.T) {
	transp := channel.NewTransport()

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(true))

	sock, err := z.NewSenderSocket(transp, "127.0.0.1:0")
	require.NoError(t, err)

	node.AddPeer(sock.GetAddress())

	callId, err := node.DialPeer(sock.GetAddress())
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Check the node is dialing
	require.Equal(t, node.CallLineState(), types.Dialing)

	dialMsg := types.DialMsg{
		CallId:         callId,
		Caller:         sock.GetAddress(),
		PubId:          impl.RandomPubId(),
		PublicKeyBytes: z.GetRandBytes(t),
	}

	transpMsg, err := node.GetRegistry().MarshalMessage(dialMsg)
	require.NoError(t, err)

	header := transport.NewHeader(sock.GetAddress(), sock.GetAddress(), node.GetAddr(), 0)

	pkt := transport.Packet{
		Header: &header,
		Msg:    &transpMsg,
	}

	err = sock.Send(node.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(time.Second)

	// Check sock ins
	sockIns := sock.GetIns()

	require.Equal(t, len(sockIns), 1)
	require.Equal(t, sockIns[0].Msg.Type, "DialMsg")

	// Check node is in call with socket
	require.Equal(t, node.CallLineState(), types.InCall)
	nodeCallMembers := node.GetGroupCallMembers()

	require.Equal(t, len(nodeCallMembers), 1)

	_, inCall := nodeCallMembers[sock.GetAddress()]
	require.True(t, inCall)

	node.EndCall()
	require.Equal(t, node.CallLineState(), types.Idle)

}

func TestPeercord_DialTimeout(t *testing.T) {
	transp := channel.NewTransport()

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(true))

	sock, err := z.NewSenderSocket(transp, "127.0.0.1:0")
	require.NoError(t, err)

	node.AddPeer(sock.GetAddress())

	_, err = node.DialPeer(sock.GetAddress())
	require.NoError(t, err)

	// Check the node is dialing
	require.Equal(t, node.CallLineState(), types.Dialing)

	time.Sleep(5 * time.Second)

	// Check the node is idle
	require.Equal(t, node.CallLineState(), types.Idle)

}
