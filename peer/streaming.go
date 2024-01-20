package peer

import "go.dedis.ch/cs438/types"

// Streaming defines the interface for reading, sending and displaying audio and video bytes.
type Streaming interface {
	// GetNextVideoBytes returns a byte array containing video bytes to send.
	GetNextVideoBytes() []byte
	// GetNextAudioBytes returns a byte array containing audio bytes to send.
	GetNextAudioBytes() []byte
	// GetNextCallDataMessage packages the next audio and video stream packets into a message.
	// Under the hood, calls GetNextVideoBytes and GetNextAudioBytes.
	GetNextCallDataMessage() types.CallDataMessage

	GetAudioThroughput() float64
	GetVideoThroughput() float64
}
