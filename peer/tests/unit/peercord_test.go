package unit

import (
	"crypto/x509"
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
		CallId: callId,
		Caller: sock.GetAddress(),
		PubId:  impl.RandomPubId(),
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

func TestPeercord_PKHeartbeat(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(true), z.WithHeartbeat(time.Second))
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAutostart(true), z.WithHeartbeat(time.Second))

	node1.AddPeer(node2.GetAddr())

	time.Sleep(700 * time.Millisecond)

	// Check the nodes received heartbeats
	node1Ins := node1.GetIns()
	node2Ins := node2.GetIns()

	require.NotEqual(t, len(node1Ins), 0) // We have messages
	require.NotEqual(t, len(node2Ins), 0) // We have messages

	// Check node 1 received node 2 data sucesfully

	node2PK := node2.GetPK()
	node2PKBytes, err := x509.MarshalPKIXPublicKey(&node2PK)

	require.NoError(t, err)

	node2PubID := node2.GetPubId()

	node1Verified, node1Received := node1.VerifyPID(node2.GetAddr(), node2PubID, node2PKBytes)

	require.True(t, node1Received)
	require.True(t, node1Verified)

	// Check node 2 received node 1 data sucesfully

	node1PK := node1.GetPK()
	node1PKBytes, err := x509.MarshalPKIXPublicKey(&node1PK)

	require.NoError(t, err)

	node1PubID := node1.GetPubId()

	node2Verified, node2Received := node2.VerifyPID(node1.GetAddr(), node1PubID, node1PKBytes)

	require.True(t, node2Received)
	require.True(t, node2Verified)

}
