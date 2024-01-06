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

func Test_MulticastListener(t *testing.T) {
	transp := channel.NewTransport()

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node.Stop()

	sock, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock.Close()

	node.AddPeer(sock.GetAddress())

	// Join an existing multicast group
	require.NoError(t, node.JoinMulticastGroup(sock.GetAddress(), "fake_id"))

	// The node should have sent one message
	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)

	ins := sock.GetIns()
	require.Len(t, ins, 1)
	require.Equal(t, sock.GetAddress(), ins[0].Header.Destination)
	require.Equal(t, "join multicast group request", ins[0].Msg.Type)

	// Leave the multicast group
	require.NoError(t, node.LeaveMulticastGroup(sock.GetAddress(), "fake_id"))

	// The node should have sent another message
	sock.Recv(time.Millisecond * 10)
	sock.Recv(time.Millisecond * 10)

	ins = sock.GetIns()
	require.Len(t, ins, 2)
	require.Equal(t, sock.GetAddress(), ins[1].Header.Destination)
	require.Equal(t, "leave multicast group request", ins[1].Msg.Type)
}

func Test_MulticastSender(t *testing.T) {
	transp := channel.NewTransport()

	//fake := z.NewFakeMessage(t)

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

	// Create a new multicast group
	id := node.NewMulticastGroup()

	// Delete the multicast group
	require.NoError(t, node.DeleteMulticastGroup(id))

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
	/*outs := node.GetOuts()
	require.Len(t, outs, 2)
	require.Equal(t, outs[0].Header.Destination, sock1.GetAddress())
	require.Equal(t, outs[1].Header.Destination, sock3.GetAddress())*/
}

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
