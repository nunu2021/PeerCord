package udp

import (
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cs438/transport"
	"strings"
	"testing"
	"time"
)

func TestScenario(t *testing.T) {
	udp := NewUDP()

	// Create UDP sockets
	socket1, err := udp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)

	socket2, err := udp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)

	// Check that the OS chose a random port
	addr := socket1.GetAddress()
	addrParts := strings.Split(addr, ":")

	require.Len(t, addrParts, 2)
	require.Equal(t, "127.0.0.1", addrParts[0])
	require.NotEqual(t, "0", addrParts[1])

	// Send a packet
	err = socket1.Send(socket2.GetAddress(), transport.Packet{
		Header: &transport.Header{},
		Msg: &transport.Message{
			Type: "hey",
		},
	}, 0)
	require.NoError(t, err)

	// Receive the packet
	pkt, err := socket2.Recv(time.Second)
	require.NoError(t, err)
	require.Equal(t, "hey", pkt.Msg.Type)

	// Try to receive a packet -> timeout
	_, err = socket1.Recv(time.Second)
	require.Error(t, err)

	// Close the sockets
	err = socket1.Close()
	require.NoError(t, err)

	err = socket2.Close()
	require.NoError(t, err)

	// Close again a socket - produces an error
	err = socket1.Close()
	require.Error(t, err)
}
