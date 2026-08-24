package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// TrustStore provides an interface for installing and removing root CA certificates in system trust stores.
type TrustStore interface {
	InstallCA(certPEM []byte, certName string) error
	UninstallCA(certName string) error
	IsInstalled(certName string) (bool, error)
}

// SystemTrustStore implements TrustStore for the host operating system.
type SystemTrustStore struct {
	runner CommandRunner
}

// CommandRunner abstracts command execution for testability.
type CommandRunner interface {
	Run(name string, args ...string) ([]byte, error)
	LookPath(file string) (string, error)
}

type osCommandRunner struct{}

func (r *osCommandRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func (r *osCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// NewSystemTrustStore creates a TrustStore targeting the running OS.
func NewSystemTrustStore() *SystemTrustStore {
	return &SystemTrustStore{runner: &osCommandRunner{}}
}

// NewCustomTrustStore creates a SystemTrustStore with a custom CommandRunner for testing.
func NewCustomTrustStore(runner CommandRunner) *SystemTrustStore {
	return &SystemTrustStore{runner: runner}
}

// InstallCA installs the given PEM certificate into the OS system trust store.
func (s *SystemTrustStore) InstallCA(certPEM []byte, certName string) error {
	if len(certPEM) == 0 {
		return errors.New("empty certificate PEM")
	}
	if certName == "" {
		certName = "fabric-ca"
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("invalid certificate PEM block")
	}

	switch runtime.GOOS {
	case "linux":
		return s.installLinux(certPEM, certName)
	case "darwin":
		return s.installDarwin(certPEM, certName)
	case "windows":
		return s.installWindows(certPEM, certName)
	default:
		return fmt.Errorf("unsupported operating system for trust store: %s", runtime.GOOS)
	}
}

// UninstallCA removes the root certificate from the OS system trust store.
func (s *SystemTrustStore) UninstallCA(certName string) error {
	if certName == "" {
		certName = "fabric-ca"
	}

	switch runtime.GOOS {
	case "linux":
		return s.uninstallLinux(certName)
	case "darwin":
		return s.uninstallDarwin(certName)
	case "windows":
		return s.uninstallWindows(certName)
	default:
		return fmt.Errorf("unsupported operating system for trust store: %s", runtime.GOOS)
	}
}

// IsInstalled checks if the named certificate is already present in the target store path.
func (s *SystemTrustStore) IsInstalled(certName string) (bool, error) {
	if certName == "" {
		certName = "fabric-ca"
	}

	switch runtime.GOOS {
	case "linux":
		destPath, _, _ := s.detectLinuxTrustPath(certName)
		if destPath == "" {
			return false, nil
		}
		_, err := os.Stat(destPath)
		return err == nil, nil
	default:
		return false, nil
	}
}

// Linux implementation
func (s *SystemTrustStore) detectLinuxTrustPath(certName string) (destPath, updateCmd string, updateArgs []string) {
	// Debian / Ubuntu / Mint
	if _, err := s.runner.LookPath("update-ca-certificates"); err == nil {
		return filepath.Join("/usr/local/share/ca-certificates", certName+".crt"), "update-ca-certificates", nil
	}
	// RHEL / CentOS / Fedora / Rocky
	if _, err := s.runner.LookPath("update-ca-trust"); err == nil {
		return filepath.Join("/etc/pki/ca-trust/source/anchors", certName+".crt"), "update-ca-trust", []string{"extract"}
	}
	// Arch / openSUSE
	if _, err := s.runner.LookPath("trust"); err == nil {
		return filepath.Join("/etc/ca-certificates/trust-source/anchors", certName+".crt"), "trust", []string{"extract-compat"}
	}
	// Generic fallback
	return filepath.Join("/usr/local/share/ca-certificates", certName+".crt"), "update-ca-certificates", nil
}

func (s *SystemTrustStore) installLinux(certPEM []byte, certName string) error {
	destPath, updateCmd, updateArgs := s.detectLinuxTrustPath(certName)

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create ca certs directory (may require sudo): %w", err)
	}

	if err := os.WriteFile(destPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s (may require sudo): %w", destPath, err)
	}

	if _, err := s.runner.LookPath(updateCmd); err == nil {
		out, err := s.runner.Run(updateCmd, updateArgs...)
		if err != nil {
			return fmt.Errorf("failed to update CA trust store (%s): %s: %w", updateCmd, string(out), err)
		}
	}
	return nil
}

func (s *SystemTrustStore) uninstallLinux(certName string) error {
	destPath, updateCmd, updateArgs := s.detectLinuxTrustPath(certName)

	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s (may require sudo): %w", destPath, err)
	}

	if _, err := s.runner.LookPath(updateCmd); err == nil {
		out, err := s.runner.Run(updateCmd, updateArgs...)
		if err != nil {
			return fmt.Errorf("failed to update CA trust store (%s): %s: %w", updateCmd, string(out), err)
		}
	}
	return nil
}

// macOS implementation
func (s *SystemTrustStore) installDarwin(certPEM []byte, certName string) error {
	tmpFile, err := os.CreateTemp("", certName+"-*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(certPEM); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	// Add to System Keychain (or Login keychain fallback)
	out, err := s.runner.Run("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", tmpFile.Name())
	if err != nil {
		// Fallback to login keychain if system keychain is unauthorized
		home, _ := os.UserHomeDir()
		loginKeychain := filepath.Join(home, "Library/Keychains/login.keychain-db")
		out, err = s.runner.Run("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", loginKeychain, tmpFile.Name())
		if err != nil {
			return fmt.Errorf("failed to add trusted cert to macOS keychain: %s: %w", string(out), err)
		}
	}
	return nil
}

func (s *SystemTrustStore) uninstallDarwin(certName string) error {
	block, _ := pem.Decode([]byte(certName))
	commonName := certName
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			commonName = cert.Subject.CommonName
		}
	}

	out, err := s.runner.Run("security", "delete-certificate", "-c", commonName, "/Library/Keychains/System.keychain")
	if err != nil {
		home, _ := os.UserHomeDir()
		loginKeychain := filepath.Join(home, "Library/Keychains/login.keychain-db")
		s.runner.Run("security", "delete-certificate", "-c", commonName, loginKeychain)
	}
	_ = out
	return nil
}

// Windows implementation
func (s *SystemTrustStore) installWindows(certPEM []byte, certName string) error {
	tmpFile, err := os.CreateTemp("", certName+"-*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(certPEM); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	out, err := s.runner.Run("certutil", "-addstore", "-f", "ROOT", tmpFile.Name())
	if err != nil {
		return fmt.Errorf("certutil addstore failed: %s: %w", string(out), err)
	}
	return nil
}

func (s *SystemTrustStore) uninstallWindows(certName string) error {
	out, err := s.runner.Run("certutil", "-delstore", "ROOT", certName)
	if err != nil {
		return fmt.Errorf("certutil delstore failed: %s: %w", string(out), err)
	}
	return nil
}

// InMemoryTrustStore provides an in-memory test double for unit tests.
type InMemoryTrustStore struct {
	mu        sync.RWMutex
	installed map[string][]byte
}

// NewInMemoryTrustStore creates an in-memory TrustStore.
func NewInMemoryTrustStore() *InMemoryTrustStore {
	return &InMemoryTrustStore{
		installed: make(map[string][]byte),
	}
}

func (m *InMemoryTrustStore) InstallCA(certPEM []byte, certName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("invalid certificate PEM block")
	}

	m.installed[certName] = bytes.Clone(certPEM)
	return nil
}

func (m *InMemoryTrustStore) UninstallCA(certName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.installed, certName)
	return nil
}

func (m *InMemoryTrustStore) IsInstalled(certName string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.installed[certName]
	return ok, nil
}
