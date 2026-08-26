package updater_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fabric/internal/updater"
)

func TestNormalizeArch(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"x86_64", "amd64"},
		{"amd64", "amd64"},
		{"aarch64", "arm64"},
		{"arm64", "arm64"},
		{"armv7l", "arm"},
		{"armhf", "arm"},
		{"arm", "arm"},
		{"riscv64", "riscv64"},
	}

	for _, tc := range tests {
		got := updater.NormalizeArch(tc.input)
		if got != tc.expected {
			t.Errorf("NormalizeArch(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestFetchReleaseInfo(t *testing.T) {
	mockRelease := updater.ReleaseInfo{
		TagName: "v2.5.0",
		Name:    "Fabric v2.5.0 Release",
		Assets: []updater.ReleaseAsset{
			{Name: "fabric-linux-amd64", BrowserDownloadURL: "http://example.com/fabric-linux-amd64", Size: 1024},
			{Name: "fabric-server-linux-amd64", BrowserDownloadURL: "http://example.com/fabric-server-linux-amd64", Size: 1024},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/tags/v9.9.9" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRelease)
	}))
	defer server.Close()

	ctx := context.Background()
	client := server.Client()

	u := updater.New(updater.Config{
		ReleaseAPIURL: server.URL,
		HTTPClient:    client,
	})

	// 1. Success query
	info, err := u.FetchReleaseInfo(ctx, "latest")
	if err != nil {
		t.Fatalf("FetchReleaseInfo failed: %v", err)
	}
	if info.TagName != "v2.5.0" {
		t.Errorf("expected tag 'v2.5.0', got %q", info.TagName)
	}
	if len(info.Assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(info.Assets))
	}

	// 2. 404 query
	u404 := updater.New(updater.Config{
		ReleaseAPIURL: server.URL + "/releases/tags/v9.9.9",
		HTTPClient:    client,
	})
	_, err = u404.FetchReleaseInfo(ctx, "v9.9.9")
	if err == nil {
		t.Errorf("expected error for 404 release, got nil")
	}
}

func TestRunUpdate_CheckOnly(t *testing.T) {
	mockRelease := updater.ReleaseInfo{
		TagName: "v2.5.0",
		Name:    "Fabric v2.5.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRelease)
	}))
	defer server.Close()

	var buf bytes.Buffer
	cfg := updater.Config{
		CurrentVersion: "v2.1.0",
		ReleaseAPIURL:  server.URL,
		CheckOnly:      true,
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	u := updater.New(cfg)
	if err := u.Run(context.Background()); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "An update is available: v2.1.0 -> v2.5.0") {
		t.Errorf("expected update available message, got:\n%s", out)
	}

	// Up-to-date check
	buf.Reset()
	cfg.CurrentVersion = "v2.5.0"
	u2 := updater.New(cfg)
	if err := u2.Run(context.Background()); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "Fabric is already up to date (version v2.5.0)") {
		t.Errorf("expected up to date message, got:\n%s", out)
	}
}

func TestRunUpdate_EndToEnd_WithAtomicRollback(t *testing.T) {
	tmpDir := t.TempDir()

	// Initial binaries
	oldFabric := filepath.Join(tmpDir, "fabric")
	oldServer := filepath.Join(tmpDir, "fabric-server")
	oldThread := filepath.Join(tmpDir, "fabric-thread")

	_ = os.WriteFile(oldFabric, []byte("OLD_CLI_BINARY"), 0755)
	_ = os.WriteFile(oldServer, []byte("OLD_SERVER_BINARY"), 0755)
	_ = os.WriteFile(oldThread, []byte("OLD_THREAD_BINARY"), 0755)

	newCliPayload := []byte("#!/bin/sh\necho 'NEW_CLI_v2.5.0'\n")
	newServerPayload := []byte("#!/bin/sh\necho 'NEW_SERVER_v2.5.0'\n")
	newThreadPayload := []byte("#!/bin/sh\necho 'NEW_THREAD_v2.5.0'\n")

	cliSum := sha256.Sum256(newCliPayload)
	serverSum := sha256.Sum256(newServerPayload)
	threadSum := sha256.Sum256(newThreadPayload)

	checksumsContent := fmt.Sprintf("%s  fabric-linux-amd64\n%s  fabric-server-linux-amd64\n%s  fabric-thread-linux-amd64\n",
		hex.EncodeToString(cliSum[:]),
		hex.EncodeToString(serverSum[:]),
		hex.EncodeToString(threadSum[:]),
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/release":
			rel := updater.ReleaseInfo{
				TagName: "v2.5.0",
				Name:    "Fabric v2.5.0",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rel)
		case "/downloads/fabric-linux-amd64":
			w.Write(newCliPayload)
		case "/downloads/fabric-server-linux-amd64":
			w.Write(newServerPayload)
		case "/downloads/fabric-thread-linux-amd64":
			w.Write(newThreadPayload)
		case "/downloads/checksums.txt":
			w.Write([]byte(checksumsContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var buf bytes.Buffer
	cfg := updater.Config{
		CurrentVersion: "v2.4.1",
		ReleaseAPIURL:  server.URL + "/api/release",
		DownloadURL:    server.URL + "/downloads",
		InstallDir:     tmpDir,
		UpdateAll:      true,
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	u := updater.New(cfg)
	if err := u.Run(context.Background()); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Successfully updated Fabric to v2.5.0!") {
		t.Errorf("expected success message in output, got:\n%s", out)
	}

	// Verify all binaries updated
	cliContent, _ := os.ReadFile(oldFabric)
	if string(cliContent) != string(newCliPayload) {
		t.Errorf("fabric binary not updated: got %q", string(cliContent))
	}
	serverContent, _ := os.ReadFile(oldServer)
	if string(serverContent) != string(newServerPayload) {
		t.Errorf("fabric-server binary not updated: got %q", string(serverContent))
	}
	threadContent, _ := os.ReadFile(oldThread)
	if string(threadContent) != string(newThreadPayload) {
		t.Errorf("fabric-thread binary not updated: got %q", string(threadContent))
	}

	// Verify backup files exist
	backupCli := oldFabric + ".old"
	if b, err := os.ReadFile(backupCli); err != nil || string(b) != "OLD_CLI_BINARY" {
		t.Errorf("expected backup file %s with original content, got err=%v", backupCli, err)
	}
}

func TestRunUpdate_ChecksumMismatch_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "fabric")
	_ = os.WriteFile(targetPath, []byte("ORIGINAL_FABRIC_BINARY"), 0755)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/release":
			json.NewEncoder(w).Encode(updater.ReleaseInfo{TagName: "v2.5.0"})
		case "/downloads/fabric-linux-amd64":
			w.Write([]byte("TAMPERED_PAYLOAD"))
		case "/downloads/checksums.txt":
			fakeHash := sha256.Sum256([]byte("DIFFERENT_HASH"))
			w.Write([]byte(fmt.Sprintf("%s  fabric-linux-amd64\n", hex.EncodeToString(fakeHash[:]))))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var buf bytes.Buffer
	cfg := updater.Config{
		CurrentVersion: "v2.4.1",
		ReleaseAPIURL:  server.URL + "/api/release",
		DownloadURL:    server.URL + "/downloads",
		InstallDir:     tmpDir,
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	u := updater.New(cfg)
	err := u.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error on checksum mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}

	// Original binary preserved
	content, _ := os.ReadFile(targetPath)
	if string(content) != "ORIGINAL_FABRIC_BINARY" {
		t.Errorf("expected target binary to remain original, got %q", string(content))
	}
}

func TestRunUpdate_MissingChecksum_Rejected(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "fabric")
	_ = os.WriteFile(targetPath, []byte("ORIGINAL_FABRIC_BINARY"), 0755)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/release":
			json.NewEncoder(w).Encode(updater.ReleaseInfo{TagName: "v2.5.0"})
		case "/downloads/fabric-linux-amd64":
			w.Write([]byte("BINARY_WITHOUT_CHECKSUM"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var buf bytes.Buffer
	cfg := updater.Config{
		CurrentVersion: "v2.4.1",
		ReleaseAPIURL:  server.URL + "/api/release",
		DownloadURL:    server.URL + "/downloads",
		InstallDir:     tmpDir,
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	u := updater.New(cfg)
	err := u.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error on missing checksum manifest, got nil")
	}

	// Original binary preserved
	content, _ := os.ReadFile(targetPath)
	if string(content) != "ORIGINAL_FABRIC_BINARY" {
		t.Errorf("expected target binary to remain original, got %q", string(content))
	}
}
