package meshdns

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	hostsFile   = "/etc/hosts"
	blockStart  = "# BEGIN MESHDNS OVERRIDES"
	blockEnd    = "# END MESHDNS OVERRIDES"
)

// OSAdapter implements OSEnvironment by mutating the OS's /etc/hosts file.
type OSAdapter struct {
	mu           sync.Mutex
	managedHosts map[string]string // Maps domain to IP
	hostsPath    string            // Allows overriding for testing if needed
}

// NewOSAdapter creates a new OSAdapter.
func NewOSAdapter() *OSAdapter {
	return &OSAdapter{
		managedHosts: make(map[string]string),
		hostsPath:    hostsFile,
	}
}

// AddDNSOverride adds a DNS override for the given domain.
func (a *OSAdapter) AddDNSOverride(domain string, ip string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.managedHosts[domain] = ip
	return a.flush()
}

// RemoveDNSOverride removes a DNS override for the given domain.
func (a *OSAdapter) RemoveDNSOverride(domain string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.managedHosts, domain)
	return a.flush()
}

// Close reverts all managed overrides and cleans up the hosts file block.
func (a *OSAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.managedHosts = make(map[string]string)
	return a.flush()
}

// flush writes the current state of managedHosts to the hosts file.
// It preserves existing contents outside the meshdns block.
func (a *OSAdapter) flush() error {
	content, err := os.ReadFile(a.hostsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read hosts file: %w", err)
		}
		content = []byte{}
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inBlock := false

	// Filter out the existing block
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == blockStart {
			inBlock = true
			continue
		}
		if trimmed == blockEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			newLines = append(newLines, line)
		}
	}

	// Remove trailing empty lines to avoid unbounded growth of newlines
	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	// Append the new block if we have managed hosts
	if len(a.managedHosts) > 0 {
		if len(newLines) > 0 {
			newLines = append(newLines, "") // Add an empty line before our block if file is not empty
		}
		newLines = append(newLines, blockStart)
		for domain, ip := range a.managedHosts {
			newLines = append(newLines, fmt.Sprintf("%s %s", ip, domain))
		}
		newLines = append(newLines, blockEnd)
	}

	// Ensure file ends with exactly one newline
	if len(newLines) > 0 {
		newLines = append(newLines, "")
	}

	output := strings.Join(newLines, "\n")

	f, err := os.OpenFile(a.hostsPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open hosts file for writing: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	if _, err := writer.WriteString(output); err != nil {
		return fmt.Errorf("failed to write to hosts file: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush hosts file: %w", err)
	}

	return nil
}
