package unit

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
	"testing"
	"time"
)

/*func Test_MulticastNaive(t *testing.T) {
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
}*/

// Check that a node stop forwarding messages if to a neighbor if it has stopped
// sending join messages
func Test_MulticastJoinTimeout(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0",
		z.WithMulticastJoinTimeout(3*time.Second),
		z.WithMulticastLeaveTimeout(15*time.Second))
	defer node.Stop()

	sock, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock.Close()

	node.AddPeer(sock.GetAddress())

	// Create a new multicast group
	id := node.NewMulticastGroup()

	// Make the socket join the group
	joinMsg := types.JoinMulticastGroupRequestMessage{
		GroupSender: node.GetAddr(),
		GroupID:     id,
	}
	data, err := json.Marshal(&joinMsg)
	require.NoError(t, err)

	msg := transport.Message{
		Type:    joinMsg.Name(),
		Payload: data,
	}

	header := transport.NewHeader(sock.GetAddress(), sock.GetAddress(), node.GetAddr(), 0)
	pkt := transport.Packet{Header: &header, Msg: &msg}

	require.NoError(t, sock.Send(node.GetAddr(), pkt, time.Second))

	time.Sleep(10 * time.Millisecond)

	// Send a message to the group, the socket should receive it
	require.NoError(t, node.Multicast(fake.GetNetMsg(t), id))
	time.Sleep(10 * time.Millisecond)

	nIns := node.GetIns()
	require.Len(t, nIns, 1)

	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)
	sIns := sock.GetIns()
	require.Len(t, sIns, 1)

	// Wait until the timeout expires
	time.Sleep(5 * time.Second)

	// Send a message to the group, the socket should not receive it
	require.NoError(t, node.Multicast(fake.GetNetMsg(t), id))
	time.Sleep(10 * time.Millisecond)

	nIns = node.GetIns()
	require.Len(t, nIns, 1)

	sock.Recv(time.Millisecond * 10)
	sIns = sock.GetIns()
	require.Len(t, sIns, 1)
}

// Check that a peer stops forwarding message to one of its neighbors a bit
// after receiving a leave group message.
func Test_MulticastLeaveTimeout(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0",
		z.WithMulticastJoinTimeout(time.Hour),
		z.WithMulticastLeaveTimeout(5*time.Second))
	defer node.Stop()

	sock, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock.Close()

	node.AddPeer(sock.GetAddress())

	// Create a new multicast group
	id := node.NewMulticastGroup()

	// Make the socket join the group
	joinMsg := types.JoinMulticastGroupRequestMessage{
		GroupSender: node.GetAddr(),
		GroupID:     id,
	}
	data, err := json.Marshal(&joinMsg)
	require.NoError(t, err)

	msg := transport.Message{
		Type:    joinMsg.Name(),
		Payload: data,
	}

	header := transport.NewHeader(sock.GetAddress(), sock.GetAddress(), node.GetAddr(), 0)
	pkt := transport.Packet{Header: &header, Msg: &msg}

	require.NoError(t, sock.Send(node.GetAddr(), pkt, time.Second))

	time.Sleep(10 * time.Millisecond)

	// Send a message to the group, the socket should receive it
	require.NoError(t, node.Multicast(fake.GetNetMsg(t), id))
	time.Sleep(10 * time.Millisecond)

	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)
	sIns := sock.GetIns()
	require.Len(t, sIns, 1)

	// Make the socket leave the group
	leaveMsg := types.LeaveMulticastGroupRequestMessage{
		GroupID: id,
	}
	data, err = json.Marshal(&leaveMsg)
	require.NoError(t, err)

	msg = transport.Message{
		Type:    leaveMsg.Name(),
		Payload: data,
	}

	header = transport.NewHeader(sock.GetAddress(), sock.GetAddress(), node.GetAddr(), 0)
	pkt = transport.Packet{Header: &header, Msg: &msg}

	require.NoError(t, sock.Send(node.GetAddr(), pkt, time.Second))

	// Wait a bit
	time.Sleep(time.Second)

	// Send a message to the group, the socket should still receive it
	require.NoError(t, node.Multicast(fake.GetNetMsg(t), id))
	time.Sleep(10 * time.Millisecond)

	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)
	sIns = sock.GetIns()
	require.Len(t, sIns, 2)

	// Wait until the timeout expires
	time.Sleep(5 * time.Second)

	// Send a message to the group, the socket should not receive it
	require.NoError(t, node.Multicast(fake.GetNetMsg(t), id))
	time.Sleep(10 * time.Millisecond)

	sock.Recv(time.Millisecond * 10)
	sIns = sock.GetIns()
	require.Len(t, sIns, 2)
}

// Check that a node that is part of a multicast group resends periodically
// join messages to stay in the group
func Test_MulticastResendJoin(t *testing.T) {
	transp := channel.NewTransport()

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0",
		z.WithMulticastResendJoinInterval(3*time.Second))
	defer node.Stop()

	sock, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock.Close()

	node.AddPeer(sock.GetAddress())

	// Make the peer join a fake group
	require.NoError(t, node.JoinMulticastGroup(sock.GetAddress(), "fake_id"))

	// The socket should have received the join message
	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)
	require.Len(t, sock.GetIns(), 1)

	// Wait until a new message is sent
	time.Sleep(4 * time.Second)

	// The socket should have received a new message
	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)
	require.Len(t, sock.GetIns(), 2)

	// Wait until a new message is sent
	time.Sleep(3 * time.Second)

	// The socket should have received a new message
	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)
	require.Len(t, sock.GetIns(), 3)
}
