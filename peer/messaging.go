package peer

import (
	"crypto/ecdh"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"

	"go.dedis.ch/cs438/transport"
)

// Messaging defines the functions for the basic functionalities to exchange
// messages between peers.
type Messaging interface {
	// Unicast sends a packet to a given destination. If the destination is the
	// same as the node's address, then the message must still be sent to the
	// node via its socket. Use transport.NewHeader to build the packet's
	// header.
	//
	// - implemented in HW0
	Unicast(dest string, msg transport.Message) error

	// Broadcast sends a packet asynchronously to all know destinations.
	// The node must not send the message to itself (to its socket),
	// but still process it.
	//
	// - implemented in HW1
	Broadcast(msg transport.Message) error

	// NaiveMulticast sends a packet to several destinations using several calls
	// of Unicast
	NaiveMulticast(msg transport.Message, recipients map[string]struct{}) error

	// NewMulticastGroup creates a new multicast group and returns its ID. The other
	// peers need this ID to join the group
	NewMulticastGroup() string

	// DeleteMulticastGroup deletes an existing multicast group. It sends a messages
	// to all the peers of the group to inform them of the deletion.
	DeleteMulticastGroup(id string) error

	// JoinMulticastGroup allows a peer to be added to the multicast group with the
	// given id and created by the given peer. It sends a packet containing the
	// request to join the group. It blocks until the request is accepted, retrying
	// if needed.
	JoinMulticastGroup(peer string, id string) error

	// LeaveMulticastGroup allows a peer to leave the multicast group with the
	// given id and created by the given peer. It sends a packet containing the
	// request to leave the group.
	LeaveMulticastGroup(peer string, id string) error

	// Multicast sends a message to a multicast group. The peer must be the root
	// of the tree
	Multicast(msg transport.Message, groupID string) error

	// Generate the Public ID
	GenerateKeyPair() error

	// Set the public ID with an external assumed hard to forge and verified id
	SetPublicID(id string)

	// Get the Public ID key
	GetPK() rsa.PublicKey

	// Add a public ID to the known ones
	AddPublicKey(peer, pubID string, key []byte)

	// Forget about a known public ID
	RemovePublicKey(peer string)

	// Verify the public ID
	VerifyPID(peer, pubID string, key []byte) (bool, bool)

	// Sign a message with the given key
	Sign(key, packet []byte) ([]byte, error)

	// Encrypt msg for peer with its Public Key
	EncryptOneToOne(msg []byte, peer string) ([]byte, error)

	// Decrypt msg with local Secret Key
	DecryptOneToOne(msg []byte) ([]byte, error)

	// Encrypt a packet to be sent to peer with its Public Key
	EncryptOneToOnePkt(pkt *transport.Packet, peer string) (*transport.Message, error)

	// Generate a DH curve
	GenerateDHCurve()

	// Get the local DH curve
	GetDHCurve() ecdh.Curve

	// Generate a DH key
	GenerateDHKey() (*ecdh.PrivateKey, error)

	// Get the DH local Public Key
	GetDHPK() *ecdh.PublicKey

	// Perform an ECDH key exchange exponentiation
	ECDH(remotePK *ecdh.PublicKey) ([]byte, error)

	// Get the local DH shared secret
	GetDHSharedSecret() *ecdh.PublicKey

	// Generate a DH key
	SetDHSharedSecret(secret *ecdh.PublicKey)

	// Computes whether key and the local shared secret are equal
	DHSharedSecretEqual(key *ecdh.PublicKey) bool

	// Encrypt msg with DH shared secret
	EncryptDH(msg []byte) ([]byte, error)

	// Decrypt msg with DH shared secret
	DecryptDH(msg []byte) ([]byte, error)

	// Encrypt pkt with DH shared secret
	EncryptDHPkt(pkt *transport.Packet) (*transport.Message, error)

	// Start a DH Key Exchange with receivers
	StartDHKeyExchange(receivers map[string]struct{}) error

	// Remove member from the currently running group call
	GroupCallRemove(member string) error

	// Add member to the currently running group call
	GroupCallAdd(member string) error

	// End the group call
	GroupCallEnd()

	// AddPeer adds new known addresses to the node. It must update the
	// routing table of the node. Adding ourself should have no effect.
	//
	// - implemented in HW0
	AddPeer(addr ...string)

	// GetRoutingTable returns the node's routing table. It should be a copy.
	//
	// - implemented in HW0
	GetRoutingTable() RoutingTable

	// SetRoutingEntry sets the routing entry. Overwrites it if the entry
	// already exists. If the origin is equal to the relayAddr, then the node
	// has a new neighbor (the notion of neighboors is not needed in HW0). If
	// relayAddr is empty then the record must be deleted (and the peer has
	// potentially lost a neighbor).
	//
	// - implemented in HW0
	SetRoutingEntry(origin, relayAddr string)
}

// RoutingTable defines a simple next-hop routing table. The key is the origin
// and the value the relay address. The routing table must always have an entry
// to itself as follow:
//
//	Table[myAddr] = myAddr.
//
// Table[C] = B means that to reach C, message must be sent to B, the relay.
type RoutingTable map[string]string

func (r RoutingTable) String() string {
	out := new(strings.Builder)

	out.WriteString("Origin\tRelay\n")
	out.WriteString("---\t---\n")

	for origin, relay := range r {
		fmt.Fprintf(out, "%s\t%s\n", origin, relay)
	}

	return out.String()
}

// DisplayGraph displays the routing table as a graphviz graph.
//
//	dot -Tpdf -O *.dot
func (r RoutingTable) DisplayGraph(out io.Writer) {
	fmt.Fprint(out, "digraph routing_table {\n")

	fmt.Fprintf(out, "labelloc=\"t\";")
	fmt.Fprintf(out, "label = <Routing Table <font point-size='10'><br/>"+
		"(generated %s)</font>>;\n\n", time.Now().Format("2 Jan 06 - 15:04:05"))
	fmt.Fprintf(out, "graph [fontname = \"helvetica\"];\n")
	fmt.Fprintf(out, "graph [fontname = \"helvetica\"];\n")
	fmt.Fprintf(out, "node [fontname = \"helvetica\"];\n")
	fmt.Fprintf(out, "edge [fontname = \"helvetica\"];\n\n")

	node := "NODE"

	for origin, relay := range r {
		if origin == relay {
			fmt.Fprintf(out, "\"%s\" -> \"%s\";\n", node, origin)
		} else {
			fmt.Fprintf(out, "\"%s\" -> \"%s\";\n", relay, origin)
		}
	}

	fmt.Fprint(out, "}\n")
}
