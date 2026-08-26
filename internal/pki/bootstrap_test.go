package pki_test

import (
	"os"
	"path/filepath"
	"testing"

	"fabric/internal/pki"
)

func TestBootstrapCA_NewAndExisting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-bootstrap-ca-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	domain := "mesh.test"

	// 1. Initial Bootstrap
	ca, caCertPath, err := pki.BootstrapCA(caDir, domain)
	if err != nil {
		t.Fatalf("BootstrapCA failed: %v", err)
	}
	if ca == nil {
		t.Fatal("expected non-nil CA instance")
	}
	expectedCACertPath := filepath.Join(caDir, "ca.crt")
	if caCertPath != expectedCACertPath {
		t.Errorf("expected caCertPath %s, got %s", expectedCACertPath, caCertPath)
	}

	// Verify ca.crt, ca.key exist on disk
	if _, err := os.Stat(caCertPath); err != nil {
		t.Errorf("ca.crt does not exist on disk: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.key")); err != nil {
		t.Errorf("ca.key does not exist on disk: %v", err)
	}

	// 2. Re-running BootstrapCA should be idempotent
	ca2, caCertPath2, err := pki.BootstrapCA(caDir, domain)
	if err != nil {
		t.Fatalf("Second BootstrapCA failed: %v", err)
	}
	if ca2 == nil || caCertPath2 != caCertPath {
		t.Errorf("idempotent BootstrapCA mismatch")
	}

	// Verify certificate is still valid and unchanged
	pem1, _ := os.ReadFile(caCertPath)
	pem2, _ := os.ReadFile(caCertPath2)
	if string(pem1) != string(pem2) {
		t.Errorf("expected idempotent CA cert to remain unchanged")
	}
}
