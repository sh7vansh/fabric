package pki_test

import (
	"os"
	"path/filepath"
	"testing"

	"fabric/internal/pki"
)

func TestDefaultCACandidatePaths_OrderAndEnv(t *testing.T) {
	// Setup custom env vars
	customCert := "/tmp/test-custom-ca.crt"
	customDir := "/tmp/test-ca-dir"

	t.Setenv("FABRIC_CA_CERT", customCert)
	t.Setenv("FABRIC_CA_DIR", customDir)

	paths := pki.DefaultCACandidatePaths()
	if len(paths) < 4 {
		t.Fatalf("expected at least 4 candidate paths, got %d: %v", len(paths), paths)
	}

	if paths[0] != customCert {
		t.Errorf("expected paths[0] to be %s, got %s", customCert, paths[0])
	}
	expectedFromDir := filepath.Join(customDir, "ca.crt")
	if paths[1] != expectedFromDir {
		t.Errorf("expected paths[1] to be %s, got %s", expectedFromDir, paths[1])
	}

	// Verify standard paths exist in the list
	foundEtc := false
	for _, p := range paths {
		if p == "/etc/fabric/ca.crt" || p == "/etc/fabric/ca/ca.crt" {
			foundEtc = true
			break
		}
	}
	if !foundEtc {
		t.Errorf("expected candidate paths to include standard /etc/fabric paths, got %v", paths)
	}
}

func TestFindCACert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-find-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy CA cert in temp dir
	testCertPath := filepath.Join(tmpDir, "ca.crt")
	dummyCertData := []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(testCertPath, dummyCertData, 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Explicit path
	foundPath, pem, err := pki.FindCACert(testCertPath)
	if err != nil {
		t.Fatalf("FindCACert with explicit path failed: %v", err)
	}
	if foundPath != testCertPath || string(pem) != string(dummyCertData) {
		t.Errorf("FindCACert mismatch: got path=%s data=%s", foundPath, string(pem))
	}

	// 2. Discover via FABRIC_CA_CERT env
	t.Setenv("FABRIC_CA_CERT", testCertPath)
	foundPath, pem, err = pki.FindCACert("")
	if err != nil {
		t.Fatalf("FindCACert via FABRIC_CA_CERT failed: %v", err)
	}
	if foundPath != testCertPath || string(pem) != string(dummyCertData) {
		t.Errorf("FindCACert env mismatch: got path=%s data=%s", foundPath, string(pem))
	}

	// 3. Fail when none exist
	t.Setenv("FABRIC_CA_CERT", filepath.Join(tmpDir, "nonexistent.crt"))
	t.Setenv("FABRIC_CA_DIR", filepath.Join(tmpDir, "empty-dir"))
	_, _, err = pki.FindCACert(filepath.Join(tmpDir, "nonexistent-explicit.crt"))
	if err == nil {
		t.Errorf("expected error when CA cert does not exist, got nil")
	}
}

func TestResolveCADir(t *testing.T) {
	// 1. Explicit directory
	explicit := "/custom/ca/dir"
	if dir := pki.ResolveCADir(explicit); dir != explicit {
		t.Errorf("ResolveCADir(%q) = %q, expected %q", explicit, dir, explicit)
	}

	// 2. FABRIC_CA_DIR env
	envDir := "/env/ca/dir"
	t.Setenv("FABRIC_CA_DIR", envDir)
	if dir := pki.ResolveCADir(""); dir != envDir {
		t.Errorf("ResolveCADir(\"\") with env = %q, expected %q", dir, envDir)
	}
}

