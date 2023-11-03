package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"io"
	"strings"
)

// FileSharing contains all the objects used by the file-sharing system.
// An instance of this type is a member of node.
type FileSharing struct {
	catalog peer.Catalog
}

// NewFileSharing returns an empty FileSharing object.
func NewFileSharing() FileSharing {
	return FileSharing{
		catalog: make(peer.Catalog),
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
	return n.fileSharing.catalog
}

// UpdateCatalog implements Peer.DataSharing
// It is NOT thread-safe
func (n *node) UpdateCatalog(key string, peer string) {
	_, ok := n.fileSharing.catalog[key]
	if !ok {
		n.fileSharing.catalog[key] = make(map[string]struct{})
	}

	var empty struct{}
	n.fileSharing.catalog[key][peer] = empty
}

func (n *node) downloadChunk(hash string) ([]byte, error) {
	blobStore := n.conf.Storage.GetDataBlobStore()

	// Check if we have the file locally
	buffer := blobStore.Get(hash)
	if buffer != nil {
		return buffer, nil
	}

	// Check if another peer has the file

	return nil, NonexistentFileError(hash) // TODO NonexistentChunk
}

func (n *node) Download(metahash string) ([]byte, error) {
	chunk, err := n.downloadChunk(metahash)
	if err != nil {
		n.logger.Info().Str("meta-hash", metahash).Msg("can't download file: unknown meta-hash")
		return nil, err
	}

	hashes := strings.Split(string(chunk), peer.MetafileSep)

	file := make([]byte, 0)

	for _, hash := range hashes {
		chunk, err := n.downloadChunk(hash)
		if err != nil {
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

	buffer := blobStore.Get(dataRequestMsg.Key) // Can be nil, but this is fine

	reply := types.DataReplyMessage{
		RequestID: dataRequestMsg.RequestID,
		Key:       dataRequestMsg.Key,
		Value:     buffer,
	}

	marshaledReply, err := n.conf.MessageRegistry.MarshalMessage(reply)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't marshal reply")
		return err
	}

	err = n.Unicast(pkt.Header.Source, marshaledReply)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't unicast data reply")
		return err
	}

	return nil
}
