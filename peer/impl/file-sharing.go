package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/rs/xid"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"io"
	"math/rand"
	"strings"
	"time"
)

// FileSharing contains all the objects used by the file-sharing system.
// An instance of this type is a member of node.
type FileSharing struct {
	catalog safeMap[string, map[string]struct{}]

	replyReceived safeMap[string, chan struct{}]
}

// NewFileSharing returns an empty FileSharing object.
func NewFileSharing() FileSharing {
	return FileSharing{
		catalog:       newSafeMap[string, map[string]struct{}](),
		replyReceived: newSafeMap[string, chan struct{}](),
	}
}

func (n *node) storeChunk(chunk []byte) string {
	blobStore := n.conf.Storage.GetDataBlobStore()

	sha := sha256.New()
	sha.Write(chunk)
	hash := hex.EncodeToString(sha.Sum(nil))

	chunkCopy := make([]byte, len(chunk))
	copy(chunkCopy, chunk)

	blobStore.Set(hash, chunkCopy)

	return hash
}

// Upload implements Peer.DataSharing
// Returns (meta-hash, err)
func (n *node) Upload(data io.Reader) (string, error) {
	chunk := make([]byte, n.conf.ChunkSize)
	metaHash := make([]byte, 0)

	var err error
	size, err := data.Read(chunk)

	for err == nil { // For each chunk
		hash := n.storeChunk(chunk[:size])

		// Update the metaHash
		if len(metaHash) > 0 {
			metaHash = append(metaHash, []byte(peer.MetafileSep)...)
		}
		metaHash = append(metaHash, hash...)

		size, err = data.Read(chunk)
	}

	return n.storeChunk(metaHash), nil
}

// GetCatalog implements Peer.DataSharing
// It is NOT thread-safe
func (n *node) GetCatalog() peer.Catalog {
	return peer.Catalog(n.fileSharing.catalog.internalMap())
}

// UpdateCatalog implements Peer.DataSharing
// It is NOT thread-safe
func (n *node) UpdateCatalog(key string, peer string) {
	_, ok := n.fileSharing.catalog.get(key)
	if !ok {
		n.fileSharing.catalog.set(key, make(map[string]struct{}))
	}

	entries, _ := n.fileSharing.catalog.getReference(key)
	defer n.fileSharing.catalog.unlock()

	var empty struct{}
	entries[peer] = empty
}

// TODO In case the remote peer responds with an empty value, a tampered chunk, or the backoff timeouts, the function must return an error.

// Asks a peer for a chunk. Retry if the peer doesn't answer fast enough.
func (n *node) requestChunk(peer string, hash string) ([]byte, error) {
	// Find a request ID
	requestID := xid.New().String()

	// Set a up channel to be informed when the reply has been received
	channel := make(chan struct{})
	n.fileSharing.replyReceived.set(requestID, channel)

	// Send the request
	req := types.DataRequestMessage{RequestID: requestID, Key: hash}
	err := n.marshalAndUnicast(peer, req)
	if err != nil {
		return nil, err
	}

	// Wait for the answer
	select {
	case <-channel:
		blobStore := n.conf.Storage.GetDataBlobStore()
		buffer := blobStore.Get(hash)
		if buffer == nil {
			return nil, NonexistentFileError(hash)
		}
		return buffer, nil

	case <-time.After(time.Second): // TODO timeout
		return nil, NonexistentFileError(hash)
	}
}

func (n *node) downloadChunk(hash string) ([]byte, error) {
	blobStore := n.conf.Storage.GetDataBlobStore()

	// Check if we have the file locally
	buffer := blobStore.Get(hash)
	if buffer != nil {
		return buffer, nil
	}

	// Check if another peer has the file
	entries, exists := n.fileSharing.catalog.getReference(hash)
	if exists {
		defer n.fileSharing.catalog.unlock()
	}

	if exists && len(entries) > 0 {
		remaining := rand.Intn(len(entries))

		target := ""
		for currentPeer, _ := range entries {
			if remaining == 0 {
				target = currentPeer
				break
			}
			remaining--
		}

		return n.requestChunk(target, hash)
	}

	return nil, NonexistentFileError(hash) // TODO NonexistentChunk
}

// Download implements peer.DataSharing
// It is thread-safe, it blocks until the file is completely downloaded
func (n *node) Download(metahash string) ([]byte, error) {
	chunk, err := n.downloadChunk(metahash)
	if err != nil {
		// TODO test type of error
		n.logger.Info().Str("meta-hash", metahash).Err(err).Msg("can't download file")
		n.logger.Info().Str("meta-hash", metahash).Err(err).Msg("can't download file: unknown meta-hash")
		return nil, err
	}

	hashes := strings.Split(string(chunk), peer.MetafileSep)

	file := make([]byte, 0)

	for _, hash := range hashes {
		chunk, err := n.downloadChunk(hash)
		if err != nil {
			// TODO test type of error
			n.logger.Info().Str("hash", hash).Msg("can't download file: unknown hash")
			return nil, err
		}

		file = append(file, chunk...)
	}

	return file, nil
}

func (n *node) receiveDataRequest(msg types.Message, pkt transport.Packet) error {
	dataRequestMsg, ok := msg.(*types.DataRequestMessage)
	if !ok {
		panic("not a data request message")
	}

	blobStore := n.conf.Storage.GetDataBlobStore()

	reply := types.DataReplyMessage{
		RequestID: dataRequestMsg.RequestID,
		Key:       dataRequestMsg.Key,
		Value:     blobStore.Get(dataRequestMsg.Key), // Can be nil, but this is fine
	}

	err := n.marshalAndUnicast(pkt.Header.Source, reply)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send data reply")
		return err
	}

	return nil
}

func (n *node) receiveDataReply(msg types.Message, pkt transport.Packet) error {
	dataReplyMsg, ok := msg.(*types.DataReplyMessage)
	if !ok {
		panic("not a data reply message")
	}

	// TODO check the validity message

	// Store the data
	blobStore := n.conf.Storage.GetDataBlobStore()
	blobStore.Set(dataReplyMsg.Key, dataReplyMsg.Value)

	// Inform the download thread that a reply has been received
	channel, exists := n.fileSharing.replyReceived.get(dataReplyMsg.RequestID)
	if !exists {
		n.logger.Info().Msg("unexpected data reply received")
		return nil
	}
	var emptyStruct struct{}
	channel <- emptyStruct

	return nil
}
