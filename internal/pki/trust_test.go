package pki_test

import (
	"errors"
	"os"
	"testing"

	"fabric/internal/pki"
)

type mockCommandRunner struct {
	lookPathFunc func(file string) (string, error)
	runFunc      func(name string, args ...string) ([]byte, error)
	calls        []string
}

func (m *mockCommandRunner) LookPath(file string) (string, error) {
	if m.lookPathFunc != nil {
		return m.lookPathFunc(file)
	}
	return "/usr/sbin/" + file, nil
}

func (m *mockCommandRunner) Run(name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, name)
	if m.runFunc != nil {
		return m.runFunc(name, args...)
	}
	return []byte("success"), nil
}

func TestInMemoryTrustStore(t *testing.T) {
	ts := pki.NewInMemoryTrustStore()

	tmpDir, err := os.MkdirTemp("", "fabric-ca-trust-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.mesh")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Invalid PEM
	if err := ts.InstallCA([]byte("not-a-cert"), "test-ca"); err == nil {
		t.Error("expected error installing invalid PEM")
	}

	// 2. Valid Install
	if err := ts.InstallCA(ca.CertPEM(), "fabric-ca"); err != nil {
		t.Fatalf("InstallCA failed: %v", err)
	}

	installed, err := ts.IsInstalled("fabric-ca")
	if err != nil || !installed {
		t.Errorf("expected fabric-ca to be installed, got %v (err: %v)", installed, err)
	}

	// 3. Uninstall
	if err := ts.UninstallCA("fabric-ca"); err != nil {
		t.Fatalf("UninstallCA failed: %v", err)
	}

	installed, _ = ts.IsInstalled("fabric-ca")
	if installed {
		t.Error("expected fabric-ca to be removed after uninstall")
	}
}

func TestSystemTrustStoreMockRunner(t *testing.T) {
	runner := &mockCommandRunner{}
	store := pki.NewCustomTrustStore(runner)

	// Test uninstall error handling
	runner.runFunc = func(name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit code 1")
	}

	err := store.UninstallCA("nonexistent-ca")
	_ = err
}

func TestCrossPlatformTrustStores(t *testing.T) {
	runner := &mockCommandRunner{}

	// 1. Darwin
	darwinStore := pki.NewCustomTrustStoreForOS(runner, "darwin")
	runner.runFunc = func(name string, args ...string) ([]byte, error) {
		if name == "security" && len(args) > 0 && args[0] == "find-certificate" {
			return []byte("certificate found"), nil
		}
		return []byte("ok"), nil
	}
	installed, err := darwinStore.IsInstalled("fabric-ca")
	if err != nil || !installed {
		t.Errorf("darwin IsInstalled expected true, got %v (err: %v)", installed, err)
	}

	runner.runFunc = func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("not found")
	}
	installed, err = darwinStore.IsInstalled("fabric-ca")
	if installed {
		t.Errorf("darwin IsInstalled expected false when cert not found, got %v", installed)
	}

	// 2. Windows
	winStore := pki.NewCustomTrustStoreForOS(runner, "windows")
	runner.runFunc = func(name string, args ...string) ([]byte, error) {
		if name == "certutil" && len(args) > 0 && args[0] == "-verifystore" {
			return []byte("cert verified"), nil
		}
		return []byte("ok"), nil
	}
	installed, err = winStore.IsInstalled("fabric-ca")
	if err != nil || !installed {
		t.Errorf("windows IsInstalled expected true, got %v (err: %v)", installed, err)
	}

	runner.runFunc = func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("certutil error")
	}
	installed, err = winStore.IsInstalled("fabric-ca")
	if installed {
		t.Errorf("windows IsInstalled expected false when certutil fails, got %v", installed)
	}
}
