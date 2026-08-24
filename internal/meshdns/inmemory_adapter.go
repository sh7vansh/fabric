package meshdns

import (
	"sync"
)

// InMemoryAdapter is an in-memory implementation of the OSEnvironment interface,
// primarily intended for testing purposes.
type InMemoryAdapter struct {
	mu        sync.RWMutex
	overrides map[string]string
}

// NewInMemoryAdapter creates a new InMemoryAdapter.
func NewInMemoryAdapter() *InMemoryAdapter {
	return &InMemoryAdapter{
		overrides: make(map[string]string),
	}
}

// AddDNSOverride adds a DNS override to the in-memory store.
func (a *InMemoryAdapter) AddDNSOverride(domain string, ip string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.overrides[domain] = ip
	return nil
}

// RemoveDNSOverride removes a DNS override from the in-memory store.
func (a *InMemoryAdapter) RemoveDNSOverride(domain string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.overrides, domain)
	return nil
}

// Close clears all overrides from the in-memory store.
func (a *InMemoryAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.overrides = make(map[string]string)
	return nil
}

// GetOverride allows tests to query the current state of an override.
func (a *InMemoryAdapter) GetOverride(domain string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ip, ok := a.overrides[domain]
	return ip, ok
}
