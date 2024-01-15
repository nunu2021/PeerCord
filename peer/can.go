package peer

import (
	"go.dedis.ch/cs438/types"
)

type CAN interface {
    // Adds a node to the list of IP addresses of nodes in the CAN
    // maintained by the bootstrap node
	AddNodeBootstrap(addr string)

    // Returns the list of IP addresses in the bootstrap node
	GetNodeList() []string

    // Hashes an IP address to a 3D point
    Hash(ip string) types.Point

    // Joins the DHT
    JoinDHT() error

    // Set the trust of a node
    SetTrust(node string, trustValue float64) error

    // Get the trust of a node
    GetTrust(node string) (float64, error)

    // -------------------------------------------------
    // Functions to return different values in the CAN
    // -------------------------------------------------

    // ReturnDHTArea(reality int) types.Zone

    // ReturnDHTSequencedArea(reality int) types.SequencedZone

    // ReturnDHTNeighbors(reality int) map[string]types.SequencedZone

    // ReturnBootstrapNodes() []string

    // ReturnDHTPoints(reality int) map[string]float64

    // NeighborsToStringLocked(reality int) string

    // PointsToString(reality int) string

    // -------------------------------
    // Helper functions (for testing)
    // -------------------------------

    // Overlap1D(l1x uint16, r1x uint16, l2x uint16, r2x uint16) bool

    // BordersZone(z types.Zone, zNew types.Zone) bool
}
