// TODO encode in hexadecimal instead of string() and byte[]() conversions?

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

	// Packet ID of all the requests that have been received
	// It is used to prevent answering to duplicate packets
	requestsReceived map[string]struct{}
}

// NewFileSharing returns an empty FileSharing object.
func NewFileSharing() FileSharing {
	return FileSharing{
		catalog:               newSafeMap[string, map[string]struct{}](),
		chunkRepliesReceived:  newSafeMap[string, chan struct{}](),
		searchRepliesReceived: newSafeMap[string, chan struct{}](),
		requestsReceived:      make(map[string]struct{}),
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
func (n *node) GetCatalog() peer.Catalog {
	internalMap := n.fileSharing.catalog.internalMap()
	defer n.fileSharing.catalog.unlock()

	catalog := make(peer.Catalog)

	for hash, peersAddr := range internalMap {
		catalog[hash] = make(map[string]struct{})
		for peerAddr := range peersAddr {
			var empty struct{}
			catalog[hash][peerAddr] = empty
		}
	}

	return catalog
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
func (n *node) requestChunk(peer string, hash string, currentTry uint) ([]byte, error) {
	requestID := xid.New().String()

	// Too many retries
	if currentTry == n.conf.BackoffDataRequest.Retry {
		return nil, NonExistentChunk(hash)
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
			return nil, NonExistentChunk(hash)
		}
		return buffer, nil

	case <-time.After(timeout):
		return n.requestChunk(peer, hash, currentTry+1)
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
		for currentPeer := range entries {
			if remaining == 0 {
				target = currentPeer
				break
			}
			remaining--
		}

		return n.requestChunk(target, hash, 0)
	}

	return nil, NonExistentChunk(hash)
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

	// Detect duplicates
	_, exists := n.fileSharing.requestsReceived[dataRequestMsg.RequestID]
	if exists {
		return nil
	}
	var empty struct{}
	n.fileSharing.requestsReceived[dataRequestMsg.RequestID] = empty

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

func (n *node) sendSearchRequestToNeighbors(requestID string, origin string, reg regexp.Regexp, totalBudget uint, forbiddenNeighbor string) error {
	neighbors := n.routingTable.neighbors(n.GetAddress())

	// Remove the forbidden neighbor
	for i, neighbor := range neighbors {
		if neighbor == forbiddenNeighbor {
			neighbors = append(neighbors[:i], neighbors[i+1:]...)
			break
		}
	}

	if len(neighbors) == 0 {
		return nil
	}

	rand.Shuffle(len(neighbors), func(i, j int) {
		neighbors[i], neighbors[j] = neighbors[j], neighbors[i]
	})

	budgetPerRequest := totalBudget / uint(len(neighbors))
	remainingBudget := totalBudget - budgetPerRequest*uint(len(neighbors))

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
			RequestID: requestID,
			Origin:    origin,
			Pattern:   reg.String(),
			Budget:    budget,
		}

		err := n.sendMsgToNeighbor(req, neighbor)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't send request")
			return err
		}
	}

	return nil
}

// SearchAll implements peer.DataSharing
func (n *node) SearchAll(reg regexp.Regexp, budget uint, timeout time.Duration) ([]string, error) {
	requestID := xid.New().String()

	err := n.sendSearchRequestToNeighbors(requestID, n.GetAddress(), reg, budget, "")
	if err != nil {
		n.logger.Error().Err(err).Msg("can't send search request")
		return nil, err
	}

	// Wait for the answers
	time.Sleep(timeout)

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

	// Detect duplicates
	_, exists := n.fileSharing.requestsReceived[searchRequestMsg.RequestID]
	if exists {
		return nil
	}
	var empty struct{}
	n.fileSharing.requestsReceived[searchRequestMsg.RequestID] = empty

	reg := regexp.MustCompile(searchRequestMsg.Pattern)

	budget := searchRequestMsg.Budget - 1
	if budget > 0 {
		err := n.sendSearchRequestToNeighbors(searchRequestMsg.RequestID, searchRequestMsg.Origin, *reg, budget, pkt.Header.Source)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't send request to neighbor")
		}
	}

	// Look for matches
	responses := make([]types.FileInfo, 0)

	n.GetNamingStore().ForEach(func(name string, metaHash []byte) bool {
		if !reg.MatchString(name) {
			return true
		}

		metaHashStr := string(metaHash)
		chunk := n.GetDataBlobStore().Get(metaHashStr)
		if chunk == nil {
			return true
		}

		hashes := make([][]byte, 0)
		for _, hash := range strings.Split(string(chunk), peer.MetafileSep) {
			if n.GetDataBlobStore().Get(hash) != nil {
				hashes = append(hashes, []byte(hash))
			} else {
				hashes = append(hashes, nil)
			}
		}

		info := types.FileInfo{
			Name:     name,
			Metahash: metaHashStr,
			Chunks:   hashes,
		}
		responses = append(responses, info)

		return true
	})

	// Send the reply
	reply := types.SearchReplyMessage{
		RequestID: searchRequestMsg.RequestID,
		Responses: responses,
	}

	marshaled, err := n.conf.MessageRegistry.MarshalMessage(reply)
	if err != nil {
		n.logger.Error().Err(err).Msg("can't marshal the message")
		return err
	}

	replyHeader := transport.NewHeader(n.GetAddress(), n.GetAddress(), searchRequestMsg.Origin, 0)
	replyPkt := transport.Packet{Header: &replyHeader, Msg: &marshaled}

	n.logger.Info().Str("dest", pkt.Header.Source).Msg("sending packet to neighbor")
	return n.conf.Socket.Send(pkt.Header.Source, replyPkt, time.Second)
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

		for _, chunk := range answer.Chunks {
			if chunk != nil {
				n.UpdateCatalog(string(chunk), pkt.Header.Source)
			}
		}
	}

	channel, exists := n.fileSharing.searchRepliesReceived.get(searchReplyMsg.RequestID)
	if exists {
		var empty struct{}
		channel <- empty
	}

	return nil
}
