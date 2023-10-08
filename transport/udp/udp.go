package udp

import (
	"errors"
	"net"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
)

const bufferSize = 65535 // Maximal size of an UDP packet

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
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addressData)
	if err != nil {
		return nil, err
	}

	socket := Socket{conn: conn}

	return &socket, nil
}

// Socket implements a network socket using UDP. It is thread-safe.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	// Connection
	conn *net.UDPConn

	// Past sent packets. The most recent packets are at the end of the slice.
	sentPacketsMutex sync.Mutex
	sentPackets      []transport.Packet

	// Past received packets. The most recent packets are at the end of the slice.
	receivedPacketsMutex sync.Mutex
	receivedPackets      []transport.Packet
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	return s.conn.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {
	addr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return err
	}

	rawData, err := pkt.Marshal()
	if err != nil {
		return err
	}

	_, _, err = s.conn.WriteMsgUDP(rawData, nil, addr)
	if err != nil {
		return err
	}

	// Add the packet to the history
	s.sentPacketsMutex.Lock()
	s.sentPackets = append(s.sentPackets, pkt)
	s.sentPacketsMutex.Unlock()

	return nil
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {
	// Set the timeout. It may have an impact on other packets
	err := s.conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return transport.Packet{}, err
	}

	// Receive a buffer
	buffer := make([]byte, bufferSize)
	buffSize, _, err := s.conn.ReadFromUDP(buffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return transport.Packet{}, transport.TimeoutError(timeout)
		}
		return transport.Packet{}, err
	}

	// Build a packet
	pkt := transport.Packet{}
	err = pkt.Unmarshal(buffer[:buffSize])
	if err != nil {
		return transport.Packet{}, err
	}

	// Add the packet to the history
	s.receivedPacketsMutex.Lock()
	s.receivedPackets = append(s.receivedPackets, pkt)
	s.receivedPacketsMutex.Unlock()

	return pkt, nil
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.conn.LocalAddr().String()
}

// GetIns implements transport.Socket. It returns a copy of all messages
// previously received.
func (s *Socket) GetIns() []transport.Packet {
	s.receivedPacketsMutex.Lock()
	pkts := make([]transport.Packet, len(s.receivedPackets))
	copy(pkts, s.receivedPackets)
	s.receivedPacketsMutex.Unlock()
	return pkts
}

// GetOuts implements transport.Socket. It returns a copy of all messages
// // previously sent.
func (s *Socket) GetOuts() []transport.Packet {
	s.sentPacketsMutex.Lock()
	pkts := make([]transport.Packet, len(s.sentPackets))
	copy(pkts, s.sentPackets)
	s.sentPacketsMutex.Unlock()
	return pkts
}
