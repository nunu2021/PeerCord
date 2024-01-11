package types

import "fmt"


func (p Point) String() string {
    return fmt.Sprintf("(%v, %v, %v)", p[0], p[1], p[2])
}

func (z Zone) String() string {
    return fmt.Sprintf("%v - %v", z.LowerLeft.String(), z.UpperRight.String())
}

// ----------------------------
// BootstrapRequestMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m BootstrapRequestMessage) NewEmpty() Message {
	return &BootstrapRequestMessage{}
}

// Name implements types.Message.
func (m BootstrapRequestMessage) Name() string {
	return "BootstrapRequestMessage"
}

// String implements types.Message.
func (m BootstrapRequestMessage) String() string {
	return fmt.Sprintf("{BootstrapRequestMessage}")
}

// HTML implements types.Message.
func (m BootstrapRequestMessage) HTML() string {
	return m.String()
}


// ----------------------------
// BootstrapResponseMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m BootstrapResponseMessage) NewEmpty() Message {
	return &BootstrapResponseMessage{}
}

// Name implements types.Message.
func (m BootstrapResponseMessage) Name() string {
	return "BootstrapResponseMessage"
}

// String implements types.Message.
func (m BootstrapResponseMessage) String() string {
    return fmt.Sprintf("{BootstrapResponseMessage}: %v", m.IPAddrs)
}

// HTML implements types.Message.
func (m BootstrapResponseMessage) HTML() string {
	return m.String()
}

// ----------------------------
// BootstrapRequestMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m UpdateBootstrapMessage) NewEmpty() Message {
	return &UpdateBootstrapMessage{}
}

// Name implements types.Message.
func (m UpdateBootstrapMessage) Name() string {
	return "UpdateBootstrapMessage"
}

// String implements types.Message.
func (m UpdateBootstrapMessage) String() string {
	return fmt.Sprintf("{UpdateBootstrapMessage}")
}

// HTML implements types.Message.
func (m UpdateBootstrapMessage) HTML() string {
	return m.String()
}

// ----------------------------
// DHTJoinRequestMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m DHTJoinRequestMessage) NewEmpty() Message {
	return &DHTJoinRequestMessage{}
}

// Name implements types.Message.
func (m DHTJoinRequestMessage) Name() string {
	return "DHTJoinRequestMessage"
}

// String implements types.Message.
func (m DHTJoinRequestMessage) String() string {
    return fmt.Sprintf("{DHTJoinRequestMessage}: %v", m.Destination.String())
}

// HTML implements types.Message.
func (m DHTJoinRequestMessage) HTML() string {
	return m.String()
}


// ----------------------------
// DHTJoinAcceptMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m DHTJoinAcceptMessage) NewEmpty() Message {
	return &DHTJoinAcceptMessage{}
}

// Name implements types.Message.
func (m DHTJoinAcceptMessage) Name() string {
	return "DHTJoinAcceptMessage"
}

// String implements types.Message.
func (m DHTJoinAcceptMessage) String() string {
    return fmt.Sprintf("{DHTJoinAcceptMessage}: Lower Left: %v, Upper Right: %v, Neighbors: %v", m.Area.LowerLeft.String(), m.Area.UpperRight.String(), m.Neighbors)
}

// HTML implements types.Message.
func (m DHTJoinAcceptMessage) HTML() string {
	return m.String()
}

// ----------------------------
// DHTUpdateNeighborsMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m DHTUpdateNeighborsMessage) NewEmpty() Message {
	return &DHTUpdateNeighborsMessage{}
}

// Name implements types.Message.
func (m DHTUpdateNeighborsMessage) Name() string {
	return "DHTUpdateNeighborsMessage"
}

// String implements types.Message.
func (m DHTUpdateNeighborsMessage) String() string {
    return fmt.Sprintf("{DHTUpdateNeighborsMessage}: Node 1: %v -- %v, Node 2: %v -- %v", m.Node1, m.Node1Area.String(), m.Node2, m.Node2Area.String())
}

// HTML implements types.Message.
func (m DHTUpdateNeighborsMessage) HTML() string {
	return m.String()
}

// ----------------------------
// DHTQueryMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m DHTQueryMessage) NewEmpty() Message {
	return &DHTQueryMessage{}
}

// Name implements types.Message.
func (m DHTQueryMessage) Name() string {
	return "DHTQueryMessage"
}

// String implements types.Message.
func (m DHTQueryMessage) String() string {
    return fmt.Sprintf("{DHTQueryMessage}: Node %s is querying for %v", m.Source, m.Point.String())
}

// HTML implements types.Message.
func (m DHTQueryMessage) HTML() string {
	return m.String()
}

// ----------------------------
// DHTQueryResponseMessage
// ----------------------------

// // NewEmpty implements types.Message.
// func (m DHTQueryResponseMessage) NewEmpty() Message {
// 	return &DHTQueryResponseMessage{}
// }

// // Name implements types.Message.
// func (m DHTQueryResponseMessage) Name() string {
// 	return "DHTQueryResponseMessage"
// }

// // String implements types.Message.
// func (m DHTQueryResponseMessage) String() string {
//     return fmt.Sprintf("{DHTQueryResponseMessage}: %v", m.TrustValue)
// }

// // HTML implements types.Message.
// func (m DHTQueryResponseMessage) HTML() string {
// 	return m.String()
// }

// ----------------------------
// DHTSetTrustMessage
// ----------------------------

// NewEmpty implements types.Message.
func (m DHTSetTrustMessage) NewEmpty() Message {
	return &DHTSetTrustMessage{}
}

// Name implements types.Message.
func (m DHTSetTrustMessage) Name() string {
	return "DHTSetTrustMessage"
}

// String implements types.Message.
func (m DHTSetTrustMessage) String() string {
    return fmt.Sprintf("{DHTSetTrustMessage}: Node %v with trust value %v", m.Source, m.TrustValue)
}

// HTML implements types.Message.
func (m DHTSetTrustMessage) HTML() string {
	return m.String()
}

