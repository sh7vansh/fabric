package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrDeviceAlreadyExists = errors.New("device with this name or public key already exists")
	ErrDevicePublicKeyUsed = errors.New("device with this public key is already registered")
)

// DeviceEntry represents a paired client device configured on the WireGuard gateway.
type DeviceEntry struct {
	Name          string    `json:"name"`
	PublicKey     string    `json:"public_key"`
	PresharedKey  string    `json:"preshared_key,omitempty"`
	VirtualIP     string    `json:"virtual_ip"`
	AllowedIPs    []string  `json:"allowed_ips"`
	CreatedAt     time.Time `json:"created_at"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Endpoint      string    `json:"endpoint,omitempty"`
}

// DeviceStore provides atomic, crash-safe persistence for registered client devices.
type DeviceStore struct {
	mu       sync.RWMutex
	filePath string
	devices  map[string]DeviceEntry // keyed by Name
}

// NewDeviceStore creates a DeviceStore instance targeting the given file path.
func NewDeviceStore(customPath ...string) (*DeviceStore, error) {
	filePath := ""
	if len(customPath) > 0 && customPath[0] != "" {
		filePath = customPath[0]
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to determine user home directory: %w", err)
		}
		filePath = filepath.Join(home, ".fabric", "devices.json")
	}

	store := &DeviceStore{
		filePath: filePath,
		devices:  make(map[string]DeviceEntry),
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

func (s *DeviceStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var list []DeviceEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse devices file %s: %w", s.filePath, err)
	}

	s.devices = make(map[string]DeviceEntry, len(list))
	for _, d := range list {
		s.devices[d.Name] = d
	}
	return nil
}

// FilePath returns the underlying storage path.
func (s *DeviceStore) FilePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filePath
}

// List returns a slice of all stored devices.
func (s *DeviceStore) List() []DeviceEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]DeviceEntry, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d)
	}
	return out
}

// Get returns the device entry by name.
func (s *DeviceStore) Get(name string) (DeviceEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[name]
	return d, ok
}

// GetByPublicKey looks up a device by its WireGuard public key.
func (s *DeviceStore) GetByPublicKey(pubKey string) (DeviceEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, d := range s.devices {
		if d.PublicKey == pubKey {
			return d, true
		}
	}
	return DeviceEntry{}, false
}

// Add registers and persists a new device entry atomically.
func (s *DeviceStore) Add(dev DeviceEntry) error {
	if dev.Name == "" {
		return errors.New("device name cannot be empty")
	}
	if dev.PublicKey == "" {
		return errors.New("device public key cannot be empty")
	}
	if dev.VirtualIP == "" {
		return errors.New("device virtual IP cannot be empty")
	}
	if dev.CreatedAt.IsZero() {
		dev.CreatedAt = time.Now().UTC()
	}
	if len(dev.AllowedIPs) == 0 {
		dev.AllowedIPs = []string{dev.VirtualIP + "/32"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.devices[dev.Name]; exists {
		return ErrDeviceAlreadyExists
	}
	for _, d := range s.devices {
		if d.PublicKey == dev.PublicKey {
			return ErrDevicePublicKeyUsed
		}
	}

	s.devices[dev.Name] = dev
	return s.persistLocked()
}

// Update updates an existing device in the store.
func (s *DeviceStore) Update(dev DeviceEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.devices[dev.Name]; !exists {
		return ErrDeviceNotFound
	}

	s.devices[dev.Name] = dev
	return s.persistLocked()
}

// Delete removes a device by name and atomically updates disk persistence.
func (s *DeviceStore) Delete(name string) (DeviceEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dev, ok := s.devices[name]
	if !ok {
		return DeviceEntry{}, ErrDeviceNotFound
	}

	delete(s.devices, name)
	if err := s.persistLocked(); err != nil {
		// Restore in memory if write failed
		s.devices[name] = dev
		return DeviceEntry{}, err
	}

	return dev, nil
}

func (s *DeviceStore) persistLocked() error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	list := make([]DeviceEntry, 0, len(s.devices))
	for _, d := range s.devices {
		list = append(list, d)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode devices json: %w", err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", s.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write tmp device file: %w", err)
	}

	if err := os.Rename(tmpFile, s.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to atomically rename device store file: %w", err)
	}

	return nil
}
