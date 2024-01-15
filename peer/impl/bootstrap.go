package impl

import (
    "math/rand"
    "sync"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

type BootstrapNode struct {
    mu       *sync.Mutex
    NodeList []string
}

func NewBootstrap() BootstrapNode {
    return BootstrapNode{mu: &sync.Mutex{}, NodeList: []string{}}
}

// Adds node into bootstrap node's list
// If node limit is reached, replaces a random node
// with a certain probability (default = 0.75)
func (n *node) AddNodeBootstrap(addr string) {
    if !n.conf.IsBootstrap {
        return
    }

    b := &n.bootstrap
    if len(b.NodeList) < n.conf.BootstrapNodeLimit {
        b.NodeList = append(b.NodeList, addr)
    } else if (rand.Float64() < n.conf.BootstrapReplace) {
        b.NodeList[rand.Intn(n.conf.BootstrapNodeLimit)] = addr
    }
}


func (n *node) GetNodeList() []string {
    if n.conf.IsBootstrap {
        return n.bootstrap.NodeList
    }
    return []string{}
}


func (n *node) ExecBootstrapRequestMessage(msg types.Message, pkt transport.Packet) error {
    if !n.conf.IsBootstrap {
        return nil
    }

	_, ok := msg.(*types.BootstrapRequestMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.bootstrap.mu.Lock()
	defer n.bootstrap.mu.Unlock()

    n.routingTable.set(pkt.Header.Source, pkt.Header.Source)

    responseMsg := types.BootstrapResponseMessage{
        IPAddrs: n.bootstrap.NodeList,
    }

    tMsg, err := n.conf.MessageRegistry.MarshalMessage(responseMsg)
    if err != nil {
        return xerrors.Errorf("error marshalling message %v", responseMsg)
    }

    if len(n.bootstrap.NodeList) == 0 {
        n.bootstrap.NodeList = append(n.bootstrap.NodeList, pkt.Header.Source)
    }

    return n.Unicast(pkt.Header.Source, tMsg)
}

func (n *node) ExecUpdateBootstrapMessage(msg types.Message, pkt transport.Packet) error {
    if !n.conf.IsBootstrap {
        return nil
    }

	b, ok := msg.(*types.UpdateBootstrapMessage)
	if !ok {
		return xerrors.Errorf("type mismatch: %T", msg)
	}

	n.AddNodeBootstrap(b.Source)

	return nil
}
