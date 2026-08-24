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
	runner   CommandRunner
	provider osTrustProvider
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

type osTrustProvider interface {
	install(runner CommandRunner, certPEM []byte, certName string) error
	uninstall(runner CommandRunner, certName string) error
	isInstalled(runner CommandRunner, certName string) (bool, error)
}

func getProviderForOS(goos string) osTrustProvider {
	switch goos {
	case "linux":
		return &linuxTrustProvider{}
	case "darwin":
		return &darwinTrustProvider{}
	case "windows":
		return &windowsTrustProvider{}
	default:
		return &unsupportedTrustProvider{os: goos}
	}
}

// NewSystemTrustStore creates a TrustStore targeting the running OS.
func NewSystemTrustStore() *SystemTrustStore {
	return &SystemTrustStore{
		runner:   &osCommandRunner{},
		provider: getProviderForOS(runtime.GOOS),
	}
}

// NewCustomTrustStore creates a SystemTrustStore with a custom CommandRunner for testing on host OS.
func NewCustomTrustStore(runner CommandRunner) *SystemTrustStore {
	return &SystemTrustStore{
		runner:   runner,
		provider: getProviderForOS(runtime.GOOS),
	}
}

// NewCustomTrustStoreForOS creates a SystemTrustStore configured for a specific target OS and CommandRunner.
func NewCustomTrustStoreForOS(runner CommandRunner, goos string) *SystemTrustStore {
	return &SystemTrustStore{
		runner:   runner,
		provider: getProviderForOS(goos),
	}
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

	return s.provider.install(s.runner, certPEM, certName)
}

// UninstallCA removes the root certificate from the OS system trust store.
func (s *SystemTrustStore) UninstallCA(certName string) error {
	if certName == "" {
		certName = "fabric-ca"
	}

	return s.provider.uninstall(s.runner, certName)
}

// IsInstalled checks if the named certificate is already present in the target store path.
func (s *SystemTrustStore) IsInstalled(certName string) (bool, error) {
	if certName == "" {
		certName = "fabric-ca"
	}

	return s.provider.isInstalled(s.runner, certName)
}

// Linux Trust Provider
type linuxTrustProvider struct{}

func (p *linuxTrustProvider) detectPath(runner CommandRunner, certName string) (destPath, updateCmd string, updateArgs []string) {
	// Debian / Ubuntu / Mint
	if _, err := runner.LookPath("update-ca-certificates"); err == nil {
		return filepath.Join("/usr/local/share/ca-certificates", certName+".crt"), "update-ca-certificates", nil
	}
	// RHEL / CentOS / Fedora / Rocky
	if _, err := runner.LookPath("update-ca-trust"); err == nil {
		return filepath.Join("/etc/pki/ca-trust/source/anchors", certName+".crt"), "update-ca-trust", []string{"extract"}
	}
	// Arch / openSUSE
	if _, err := runner.LookPath("trust"); err == nil {
		return filepath.Join("/etc/ca-certificates/trust-source/anchors", certName+".crt"), "trust", []string{"extract-compat"}
	}
	// Generic fallback
	return filepath.Join("/usr/local/share/ca-certificates", certName+".crt"), "update-ca-certificates", nil
}

func (p *linuxTrustProvider) install(runner CommandRunner, certPEM []byte, certName string) error {
	destPath, updateCmd, updateArgs := p.detectPath(runner, certName)

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create ca certs directory (may require sudo): %w", err)
	}

	if err := os.WriteFile(destPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s (may require sudo): %w", destPath, err)
	}

	if _, err := runner.LookPath(updateCmd); err == nil {
		out, err := runner.Run(updateCmd, updateArgs...)
		if err != nil {
			return fmt.Errorf("failed to update CA trust store (%s): %s: %w", updateCmd, string(out), err)
		}
	}
	return nil
}

func (p *linuxTrustProvider) uninstall(runner CommandRunner, certName string) error {
	destPath, updateCmd, updateArgs := p.detectPath(runner, certName)

	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s (may require sudo): %w", destPath, err)
	}

	if _, err := runner.LookPath(updateCmd); err == nil {
		out, err := runner.Run(updateCmd, updateArgs...)
		if err != nil {
			return fmt.Errorf("failed to update CA trust store (%s): %s: %w", updateCmd, string(out), err)
		}
	}
	return nil
}

func (p *linuxTrustProvider) isInstalled(runner CommandRunner, certName string) (bool, error) {
	destPath, _, _ := p.detectPath(runner, certName)
	if destPath == "" {
		return false, nil
	}
	_, err := os.Stat(destPath)
	return err == nil, nil
}

// macOS (Darwin) Trust Provider
type darwinTrustProvider struct{}

func (p *darwinTrustProvider) install(runner CommandRunner, certPEM []byte, certName string) error {
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
	out, err := runner.Run("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", tmpFile.Name())
	if err != nil {
		home, _ := os.UserHomeDir()
		loginKeychain := filepath.Join(home, "Library/Keychains/login.keychain-db")
		out, err = runner.Run("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", loginKeychain, tmpFile.Name())
		if err != nil {
			return fmt.Errorf("failed to add trusted cert to macOS keychain: %s: %w", string(out), err)
		}
	}
	return nil
}

func (p *darwinTrustProvider) uninstall(runner CommandRunner, certName string) error {
	commonName := p.extractCommonName(certName)
	out, err := runner.Run("security", "delete-certificate", "-c", commonName, "/Library/Keychains/System.keychain")
	if err != nil {
		home, _ := os.UserHomeDir()
		loginKeychain := filepath.Join(home, "Library/Keychains/login.keychain-db")
		runner.Run("security", "delete-certificate", "-c", commonName, loginKeychain)
	}
	_ = out
	return nil
}

func (p *darwinTrustProvider) isInstalled(runner CommandRunner, certName string) (bool, error) {
	commonName := p.extractCommonName(certName)
	_, err := runner.Run("security", "find-certificate", "-c", commonName, "/Library/Keychains/System.keychain")
	if err == nil {
		return true, nil
	}
	home, _ := os.UserHomeDir()
	loginKeychain := filepath.Join(home, "Library/Keychains/login.keychain-db")
	_, err = runner.Run("security", "find-certificate", "-c", commonName, loginKeychain)
	return err == nil, nil
}

func (p *darwinTrustProvider) extractCommonName(certName string) string {
	block, _ := pem.Decode([]byte(certName))
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil && cert.Subject.CommonName != "" {
			return cert.Subject.CommonName
		}
	}
	return certName
}

// Windows Trust Provider
type windowsTrustProvider struct{}

func (p *windowsTrustProvider) install(runner CommandRunner, certPEM []byte, certName string) error {
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

	out, err := runner.Run("certutil", "-addstore", "-f", "ROOT", tmpFile.Name())
	if err != nil {
		return fmt.Errorf("certutil addstore failed: %s: %w", string(out), err)
	}
	return nil
}

func (p *windowsTrustProvider) uninstall(runner CommandRunner, certName string) error {
	out, err := runner.Run("certutil", "-delstore", "ROOT", certName)
	if err != nil {
		return fmt.Errorf("certutil delstore failed: %s: %w", string(out), err)
	}
	return nil
}

func (p *windowsTrustProvider) isInstalled(runner CommandRunner, certName string) (bool, error) {
	_, err := runner.Run("certutil", "-verifystore", "ROOT", certName)
	return err == nil, nil
}

// Unsupported OS Provider
type unsupportedTrustProvider struct {
	os string
}

func (p *unsupportedTrustProvider) install(runner CommandRunner, certPEM []byte, certName string) error {
	return fmt.Errorf("unsupported operating system for trust store: %s", p.os)
}

func (p *unsupportedTrustProvider) uninstall(runner CommandRunner, certName string) error {
	return fmt.Errorf("unsupported operating system for trust store: %s", p.os)
}

func (p *unsupportedTrustProvider) isInstalled(runner CommandRunner, certName string) (bool, error) {
	return false, fmt.Errorf("unsupported operating system for trust store: %s", p.os)
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
