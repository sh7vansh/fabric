package relay_test

import (
	"testing"

	"fabric/internal/protocol"
	"fabric/internal/relay"
)

func TestTopologyReconciler_EpochMonotonicity(t *testing.T) {
	rec := relay.NewTopologyReconciler("gw-server-1")

	if rec.Epoch() != 1 {
		t.Fatalf("expected initial epoch 1, got %d", rec.Epoch())
	}

	e2 := rec.IncrementEpoch()
	if e2 != 2 || rec.Epoch() != 2 {
		t.Fatalf("expected epoch 2, got %d", e2)
	}

	e3 := rec.IncrementEpoch()
	if e3 != 3 || rec.Epoch() != 3 {
		t.Fatalf("expected epoch 3, got %d", e3)
	}
}

func TestTopologyReconciler_ChecksumDeterminism(t *testing.T) {
	rec := relay.NewTopologyReconciler("gw-server-1")

	nodesSet1 := []protocol.NodeMetadata{
		{Hostname: "alpha", Domain: "fabric.mesh", Status: "online"},
		{Hostname: "beta", Domain: "fabric.mesh", Status: "online"},
		{Hostname: "gamma", Domain: "fabric.mesh", Status: "online"},
	}

	// Permuted order should produce identical checksum
	nodesSet2 := []protocol.NodeMetadata{
		{Hostname: "gamma", Domain: "fabric.mesh", Status: "online"},
		{Hostname: "alpha", Domain: "fabric.mesh", Status: "online"},
		{Hostname: "beta", Domain: "fabric.mesh", Status: "online"},
	}

	hash1 := rec.ComputeChecksum(nodesSet1)
	hash2 := rec.ComputeChecksum(nodesSet2)

	if hash1 == 0 {
		t.Errorf("expected non-zero checksum for active nodes")
	}
	if hash1 != hash2 {
		t.Errorf("checksum not deterministic: %d != %d", hash1, hash2)
	}

	// Different set should produce different checksum
	nodesSet3 := []protocol.NodeMetadata{
		{Hostname: "alpha", Domain: "fabric.mesh", Status: "online"},
		{Hostname: "beta", Domain: "fabric.mesh", Status: "online"},
	}
	hash3 := rec.ComputeChecksum(nodesSet3)
	if hash1 == hash3 {
		t.Errorf("checksum collision between different node sets: %d", hash1)
	}
}

func TestTopologyReconciler_StaleEpochRejection(t *testing.T) {
	rec := relay.NewTopologyReconciler("gw-server-1")

	peerID := "gw-peer-2"

	// 1. Initial advertisement from peer at epoch 10
	isNewer, _ := rec.ValidateAndRecordEpoch(peerID, 10, 12345)
	if !isNewer {
		t.Errorf("expected epoch 10 to be accepted")
	}

	// 2. Out-of-order or stale message with older epoch 8 (e.g. from network partition / delayed packet)
	isNewerStale, _ := rec.ValidateAndRecordEpoch(peerID, 8, 9999)
	if isNewerStale {
		t.Errorf("expected stale epoch 8 to be rejected")
	}

	// 3. Same epoch with identical checksum -> accepted, no sync needed
	isNewerSame, needsSync := rec.ValidateAndRecordEpoch(peerID, 10, 12345)
	if !isNewerSame || needsSync {
		t.Errorf("expected same epoch and hash to not need sync")
	}

	// 4. Newer epoch with different checksum -> accepted, sync triggered
	isNewerNext, needsSyncNext := rec.ValidateAndRecordEpoch(peerID, 11, 67890)
	if !isNewerNext || !needsSyncNext {
		t.Errorf("expected epoch 11 with new checksum to trigger sync")
	}
}
