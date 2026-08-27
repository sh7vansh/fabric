package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// ThreadRegistry is a thread-safe registry for direct (remote/inverted) thread entries.
type ThreadRegistry struct {
	mu      sync.RWMutex
	threads map[string]DirectThreadEntry
}

// NewThreadRegistry creates an initialized ThreadRegistry.
func NewThreadRegistry() *ThreadRegistry {
	return &ThreadRegistry{
		threads: make(map[string]DirectThreadEntry),
	}
}

// FQTN returns the fully qualified thread name (<hostname>.<domain>) or hostname.
func (e DirectThreadEntry) FQTN() string {
	if e.Domain != "" && e.Hostname != "" {
		return strings.TrimSuffix(e.Hostname, ".") + "." + strings.TrimPrefix(e.Domain, ".")
	}
	return e.Hostname
}

// Get retrieves a thread entry by key, hostname, or FQDN (case-insensitive fallback).
func (r *ThreadRegistry) Get(name string) (DirectThreadEntry, bool) {
	if r == nil {
		return DirectThreadEntry{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. Exact match
	if entry, ok := r.threads[name]; ok {
		return entry, true
	}

	// 2. Case-insensitive key match
	for k, entry := range r.threads {
		if strings.EqualFold(k, name) {
			return entry, true
		}
	}

	// 3. Hostname and FQDN match
	for _, entry := range r.threads {
		if entry.Hostname != "" && strings.EqualFold(entry.Hostname, name) {
			return entry, true
		}
		if entry.Domain != "" && entry.Hostname != "" {
			fqdn := entry.FQTN()
			if strings.EqualFold(fqdn, name) {
				return entry, true
			}
		}
	}

	return DirectThreadEntry{}, false
}

// List returns a snapshot of registered direct threads.
func (r *ThreadRegistry) List() map[string]DirectThreadEntry {
	if r == nil {
		return make(map[string]DirectThreadEntry)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make(map[string]DirectThreadEntry, len(r.threads))
	for k, v := range r.threads {
		res[k] = v
	}
	return res
}

// ListEntries returns a slice of all registered thread entries.
func (r *ThreadRegistry) ListEntries() []DirectThreadEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]DirectThreadEntry, 0, len(r.threads))
	for _, v := range r.threads {
		res = append(res, v)
	}
	return res
}

// Set adds or updates a thread entry in the registry.
func (r *ThreadRegistry) Set(name string, entry DirectThreadEntry) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.threads == nil {
		r.threads = make(map[string]DirectThreadEntry)
	}
	r.threads[name] = entry
}

// Delete removes a thread entry from the registry.
func (r *ThreadRegistry) Delete(name string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.threads, name)
}

// FindByTag returns all thread entries that contain the specified tag.
func (r *ThreadRegistry) FindByTag(tag string) []DirectThreadEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []DirectThreadEntry
	for _, entry := range r.threads {
		for _, t := range entry.Tags {
			if strings.EqualFold(t, tag) {
				matches = append(matches, entry)
				break
			}
		}
	}
	return matches
}

// Len returns the number of registered threads.
func (r *ThreadRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.threads)
}

// MarshalJSON serializes the registry map to JSON.
func (r *ThreadRegistry) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("{}"), nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.Marshal(r.threads)
}

// UnmarshalJSON deserializes JSON into the registry map, handling both map format and dual-key objects.
func (r *ThreadRegistry) UnmarshalJSON(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		if r.threads == nil {
			r.threads = make(map[string]DirectThreadEntry)
		}
		return nil
	}

	if r.threads == nil {
		r.threads = make(map[string]DirectThreadEntry)
	}

	// Try standard map[string]DirectThreadEntry
	var rawMap map[string]DirectThreadEntry
	if err := json.Unmarshal(data, &rawMap); err == nil && rawMap != nil {
		for k, v := range rawMap {
			r.threads[k] = v
		}
		return nil
	}

	// Try object with direct_threads or direct_nodes keys
	var aux struct {
		DirectThreads map[string]DirectThreadEntry `json:"direct_threads"`
		DirectNodes   map[string]DirectThreadEntry `json:"direct_nodes"`
	}
	if err := json.Unmarshal(data, &aux); err == nil && (aux.DirectThreads != nil || aux.DirectNodes != nil) {
		for k, v := range aux.DirectThreads {
			r.threads[k] = v
		}
		for k, v := range aux.DirectNodes {
			if _, exists := r.threads[k]; !exists {
				r.threads[k] = v
			}
		}
		return nil
	}

	var firstErr error
	var testMap map[string]interface{}
	if err := json.Unmarshal(data, &testMap); err != nil {
		firstErr = err
	} else {
		firstErr = fmt.Errorf("JSON object does not contain valid direct_threads or direct_nodes map")
	}

	return fmt.Errorf("failed to unmarshal thread registry JSON: %w", firstErr)
}
