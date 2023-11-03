package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"go.dedis.ch/cs438/peer"
	"io"
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

func (n *node) Download(metahash string) ([]byte, error) {
	_, ok := n.fileSharing.catalog[metahash]

	if !ok {
		n.logger.Info().Str("meta-hash", metahash).Msg("can't download file: file does not exist")
		return nil, NonexistentFileError(metahash)
	}

	return nil, nil // TODO
}
