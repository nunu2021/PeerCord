package udp

import (
	"net"
	"time"

	"go.dedis.ch/cs438/transport"
)

const bufSize = 65000

// NewUDP returns a new udp transport implementation.
func NewUDP() transport.Transport {
	return &UDP{}
}

// UDP implements a transport layer using UDP
//
// - implements transport.Transport
type UDP struct {
}

// CreateSocket implements transport.Transport
func (n *UDP) CreateSocket(address string) (transport.ClosableSocket, error) {
	addressData, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic("TODO 1")
	}

	conn, err := net.ListenUDP("udp", addressData)
	if err != nil {
		panic("TODO 2")
	}

	socket := Socket{conn: conn}

	return &socket, nil
}

// Socket implements a network socket using UDP.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	conn *net.UDPConn
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	return s.conn.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {
	panic("to be implemented in HW0")
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {
	panic("to be implemented in HW0")
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.conn.LocalAddr().String()
}

// GetIns implements transport.Socket
func (s *Socket) GetIns() []transport.Packet {
	panic("to be implemented in HW0")
}

// GetOuts implements transport.Socket
func (s *Socket) GetOuts() []transport.Packet {
	panic("to be implemented in HW0")
}
