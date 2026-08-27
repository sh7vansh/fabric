package wireguard

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceStoreAtomicPersistence(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "devices.json")

	store, err := NewDeviceStore(storePath)
	if err != nil {
		t.Fatalf("failed to create DeviceStore: %v", err)
	}

	dev1 := DeviceEntry{
		Name:      "test-phone",
		PublicKey: "pubkey-1234567890=",
		VirtualIP: "100.64.128.5",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Add(dev1); err != nil {
		t.Fatalf("failed to add device: %v", err)
	}

	// Duplicate add
	if err := store.Add(dev1); err != ErrDeviceAlreadyExists {
		t.Errorf("expected ErrDeviceAlreadyExists, got %v", err)
	}

	// Lookup
	retrieved, ok := store.Get("test-phone")
	if !ok || retrieved.VirtualIP != "100.64.128.5" {
		t.Errorf("failed to get device by name: got %v, ok %v", retrieved, ok)
	}

	retrievedByPub, ok := store.GetByPublicKey("pubkey-1234567890=")
	if !ok || retrievedByPub.Name != "test-phone" {
		t.Errorf("failed to get device by public key: got %v, ok %v", retrievedByPub, ok)
	}

	// Reload from disk to assert atomic persistence
	reloadedStore, err := NewDeviceStore(storePath)
	if err != nil {
		t.Fatalf("failed to reload DeviceStore: %v", err)
	}

	devices := reloadedStore.List()
	if len(devices) != 1 || devices[0].Name != "test-phone" {
		t.Errorf("reloaded store mismatch: %v", devices)
	}

	// Delete
	deleted, err := reloadedStore.Delete("test-phone")
	if err != nil || deleted.Name != "test-phone" {
		t.Fatalf("failed to delete device: %v", err)
	}

	if len(reloadedStore.List()) != 0 {
		t.Errorf("expected empty list after deletion")
	}

	// Reload again to assert deletion was persisted
	reloadedStore2, err := NewDeviceStore(storePath)
	if err != nil {
		t.Fatalf("failed to reload store after deletion: %v", err)
	}
	if len(reloadedStore2.List()) != 0 {
		t.Errorf("expected empty persisted store after deletion, got %v", reloadedStore2.List())
	}
}
