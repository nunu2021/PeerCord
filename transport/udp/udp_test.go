package udp

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestScenario(t *testing.T) {
	udp := NewUDP()

	// Create a UDP socket
	socket, err := udp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)

	// Check that the OS chose a random port
	addr := socket.GetAddress()
	addrParts := strings.Split(addr, ":")

	require.Len(t, addrParts, 2)
	require.Equal(t, "127.0.0.1", addrParts[0])
	require.NotEqual(t, "0", addrParts[1])

	// Close the socket
	err = socket.Close()
	require.NoError(t, err)

	// Close again - produces an error
	err = socket.Close()
	require.Error(t, err)
}
