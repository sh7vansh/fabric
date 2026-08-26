package relay

import (
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
	"sync/atomic"

	"fabric/internal/protocol"
)

// TopologyReconciler manages 64-bit monotonic generation epochs, deterministic state
// checksums, and delta synchronization across federated peer servers.
type TopologyReconciler struct {
	serverID   string
	localEpoch atomic.Uint64
	mu         sync.RWMutex
	peerEpochs map[string]uint64
	peerHashes map[string]uint32
}

// NewTopologyReconciler creates an initialized TopologyReconciler for the given server.
func NewTopologyReconciler(serverID string) *TopologyReconciler {
	r := &TopologyReconciler{
		serverID:   serverID,
		peerEpochs: make(map[string]uint64),
		peerHashes: make(map[string]uint32),
	}
	r.localEpoch.Store(1)
	return r
}

// IncrementEpoch increments the local generation epoch monotonically by 1.
func (tr *TopologyReconciler) IncrementEpoch() uint64 {
	return tr.localEpoch.Add(1)
}

// Epoch returns the current generation epoch for the local server.
func (tr *TopologyReconciler) Epoch() uint64 {
	return tr.localEpoch.Load()
}

// Checksum computes a deterministic 32-bit CRC32 checksum from a list of active threads.
func (tr *TopologyReconciler) Checksum(threads []protocol.NodeMetadata) uint32 {
	if len(threads) == 0 {
		return 0
	}

	// Sort thread representations for determinism
	items := make([]string, len(threads))
	for i, n := range threads {
		items[i] = fmt.Sprintf("%s|%s|%s", n.Hostname, n.Domain, n.Status)
	}
	sort.Strings(items)

	crc := crc32.NewIEEE()
	for _, item := range items {
		crc.Write([]byte(item))
		crc.Write([]byte{'\n'})
	}
	return crc.Sum32()
}

// ComputeChecksum is an alias for Checksum.
func (tr *TopologyReconciler) ComputeChecksum(threads []protocol.NodeMetadata) uint32 {
	return tr.Checksum(threads)
}

// ValidateAndRecordEpoch validates an incoming peer epoch.
// Returns isNewer=true if the advertisement is fresh (not stale/split-brain).
// Returns needsSync=true if the state checksum differs from the expected hash.
func (tr *TopologyReconciler) ValidateAndRecordEpoch(peerID string, epoch uint64, checksum uint32) (bool, bool) {
	if peerID == "" {
		return true, false
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	lastEpoch := tr.peerEpochs[peerID]
	lastHash := tr.peerHashes[peerID]

	// Out-of-order or stale message with older epoch
	if epoch > 0 && epoch < lastEpoch {
		return false, false
	}

	if epoch > lastEpoch {
		tr.peerEpochs[peerID] = epoch
	}

	needsSync := (checksum != 0 && checksum != lastHash)
	if checksum != 0 {
		tr.peerHashes[peerID] = checksum
	}

	return true, needsSync
}

// ResetPeer resets recorded epoch and hash state for a disconnected peer.
func (tr *TopologyReconciler) ResetPeer(peerID string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	delete(tr.peerEpochs, peerID)
	delete(tr.peerHashes, peerID)
}

// GetPeerEpoch returns the latest seen epoch for a peer.
func (tr *TopologyReconciler) GetPeerEpoch(peerID string) uint64 {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return tr.peerEpochs[peerID]
}

// GetPeerChecksum returns the latest seen checksum for a peer.
func (tr *TopologyReconciler) GetPeerChecksum(peerID string) uint32 {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return tr.peerHashes[peerID]
}
