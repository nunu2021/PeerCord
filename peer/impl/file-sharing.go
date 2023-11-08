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
	"regexp"
	"strings"
	"time"
)

// FileSharing contains all the objects used by the file-sharing system.
// An instance of this type is a member of node.
type FileSharing struct {
	catalog safeMap[string, map[string]struct{}]

	chunkRepliesReceived  safeMap[string, chan struct{}] // RequestID -> channel
	searchRepliesReceived safeMap[string, chan struct{}] // RequestID -> channel
}

// NewFileSharing returns an empty FileSharing object.
func NewFileSharing() FileSharing {
	return FileSharing{
		catalog:               newSafeMap[string, map[string]struct{}](),
		chunkRepliesReceived:  newSafeMap[string, chan struct{}](),
		searchRepliesReceived: newSafeMap[string, chan struct{}](),
	}
}

func (n *node) storeChunk(chunk []byte) string {
	blobStore := n.GetDataBlobStore()

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
	return n.fileSharing.catalog.internalMap()
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

// Asks a peer for a chunk. Retry if the peer doesn't answer fast enough.
func (n *node) requestChunk(peer string, hash string, requestID string, currentTry uint) ([]byte, error) {
	// Too many retries
	if currentTry == n.conf.BackoffDataRequest.Retry {
		return nil, NonexistentChunk(hash)
	}

	// Set a up channel to be informed when the reply has been received
	channel := make(chan struct{})
	n.fileSharing.chunkRepliesReceived.set(requestID, channel)
	defer n.fileSharing.chunkRepliesReceived.delete(requestID)

	// Send the request
	req := types.DataRequestMessage{RequestID: requestID, Key: hash}
	err := n.marshalAndUnicast(peer, req)
	if err != nil {
		return nil, err
	}

	// Compute the timeout value
	timeout := n.conf.BackoffDataRequest.Initial
	for i := uint(0); i < currentTry; i++ {
		timeout = time.Duration(n.conf.BackoffDataRequest.Factor) * timeout
	}

	// Wait for the answer
	select {
	case <-channel:
		blobStore := n.GetDataBlobStore()
		buffer := blobStore.Get(hash)
		if buffer == nil {
			return nil, NonexistentChunk(hash)
		}
		return buffer, nil

	case <-time.After(timeout):
		return n.requestChunk(peer, hash, requestID, currentTry+1)
	}
}

func (n *node) downloadChunk(hash string) ([]byte, error) {
	blobStore := n.GetDataBlobStore()

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

		return n.requestChunk(target, hash, xid.New().String(), 0)
	}

	return nil, NonexistentChunk(hash)
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

	blobStore := n.GetDataBlobStore()

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

	// Check the data
	sha := sha256.New()
	sha.Write(dataReplyMsg.Value)
	receivedHash := hex.EncodeToString(sha.Sum(nil))
	if receivedHash != dataReplyMsg.Key { // Remove from the catalog
		entry, exists := n.fileSharing.catalog.getReference(dataReplyMsg.Key)
		if exists {
			delete(entry, pkt.Header.Source)
			n.fileSharing.catalog.unlock()
		}
	}

	// Store the data
	blobStore := n.GetDataBlobStore()
	blobStore.Set(dataReplyMsg.Key, dataReplyMsg.Value)

	// Inform the download thread that a reply has been received
	channel, exists := n.fileSharing.chunkRepliesReceived.get(dataReplyMsg.RequestID)
	if !exists {
		n.logger.Info().Msg("unexpected data reply received")
		return nil
	}
	var emptyStruct struct{}
	channel <- emptyStruct

	return nil
}

// Tag implements peer.DataSharing
func (n *node) Tag(name string, metaHash string) error {
	n.GetNamingStore().Set(name, []byte(metaHash))
	return nil
}

// Resolve implements peer.DataSharing
func (n *node) Resolve(name string) string {
	return string(n.GetNamingStore().Get(name))
}

// TODO supprimer
// SearchAll returns all the names that exist matching the given regex. It
// merges results from the local storage and from the search request reply
// sent to a random neighbor using the provided budget. It makes the peer
// update its catalog and name storage according to the SearchReplyMessages
// received. Returns an empty result if nothing found. An error is returned
// in case of an exceptional event.

// SearchAll implements peer.DataSharing
func (n *node) SearchAll(reg regexp.Regexp, budget uint, timeout time.Duration) ([]string, error) {
	// Send requests to neighbors
	neighbors := n.routingTable.neighbors(n.GetAddress())
	if len(neighbors) > 0 {
		rand.Shuffle(len(neighbors), func(i, j int) {
			neighbors[i], neighbors[j] = neighbors[j], neighbors[i]
		})

		budgetPerRequest := budget / uint(len(neighbors))
		remainingBudget := budget - budgetPerRequest*uint(len(neighbors))

		for _, neighbor := range neighbors {
			// Compute the budget available for this neighbor
			budget := budgetPerRequest
			if remainingBudget > 0 {
				budget++
				remainingBudget--
			}

			if budget == 0 {
				break
			}

			// Send the request
			req := types.SearchRequestMessage{
				RequestID: xid.New().String(),
				Origin:    n.GetAddress(),
				Pattern:   reg.String(),
				Budget:    budget,
			}

			err := n.sendMsgToNeighbor(req, neighbor)
			if err != nil {
				n.logger.Error().Err(err).Msg("can't send request")
			}
		}
	}

	// Wait for the answers
	time.Sleep(10 * time.Second) // TODO change...

	// Return all the names that have been found
	names := make([]string, 0)
	n.GetNamingStore().ForEach(func(name string, _ []byte) bool {
		if reg.MatchString(name) {
			names = append(names, name)
		}
		return true
	})
	return names, nil
}

func (n *node) receiveSearchRequest(msg types.Message, pkt transport.Packet) error {
	searchRequestMsg, ok := msg.(*types.SearchRequestMessage)
	if !ok {
		panic("not a search request message")
	}

	budget := searchRequestMsg.Budget - 1
	if budget > 0 {
		// TODO forward the request
	}

	// TODO start a goroutine to avoid blocking

	// Look for matches
	responses := make([]types.FileInfo, 0)
	reg := regexp.MustCompile(searchRequestMsg.Pattern)

	n.GetNamingStore().ForEach(func(name string, metaHash []byte) bool {
		if !reg.MatchString(name) {
			return true
		}

		metaHashStr := string(metaHash)
		chunks := n.GetDataBlobStore().Get(metaHashStr)
		if chunks == nil {
			return true
		}

		info := types.FileInfo{
			Name:     name,
			Metahash: metaHashStr,
			Chunks:   nil, // TODO
		}
		responses = append(responses, info)

		return true
	})

	// Send the reply
	reply := types.SearchReplyMessage{
		RequestID: searchRequestMsg.RequestID,
		Responses: responses,
	}
	err := n.sendMsgToNeighbor(reply, pkt.Header.Source)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send search reply")
		return err
	}

	return nil
}

func (n *node) receiveSearchReply(msg types.Message, pkt transport.Packet) error {
	searchReplyMsg, ok := msg.(*types.SearchReplyMessage)
	if !ok {
		panic("not a search reply message")
	}

	// Update the naming store and the catalog
	for _, answer := range searchReplyMsg.Responses {
		n.GetNamingStore().Set(answer.Name, []byte(answer.Metahash))
		n.UpdateCatalog(answer.Metahash, pkt.Header.Source)
	}

	channel, exists := n.fileSharing.searchRepliesReceived.get(searchReplyMsg.RequestID)
	if exists {
		var empty struct{}
		channel <- empty
	}

	return nil
}
