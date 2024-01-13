package peer

import (
	"go.dedis.ch/cs438/types"
	// "go.dedis.ch/cs438/storage"
	// "go.dedis.ch/cs438/transport"
)

type CAN interface {
	AddNodeBootstrap(addr string)

	GetNodeList() []string

    Hash(ip string) types.Point

    JoinDHT() error

    SetTrust(node string, trustValue float64) error

    GetTrust(node string) (float64, error)

    ReturnDHTArea() types.Zone

    ReturnDHTSequencedArea() types.SequencedZone

    ReturnDHTNeighbors() map[string]types.SequencedZone

    ReturnBootstrapNodes() []string

    ReturnDHTPoints() map[string]float64

    NeighborsToStringLocked() string

    Overlap1D(l1x uint16, r1x uint16, l2x uint16, r2x uint16) bool

    BordersZone(z types.Zone, zNew types.Zone) bool
}
