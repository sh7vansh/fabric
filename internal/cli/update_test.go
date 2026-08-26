package cli

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
)

func TestSemverCompare(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"v2.1.0", "v2.2.0", -1},
		{"2.1.0", "2.1.0", 0},
		{"v2.1.0", "2.1.0", 0},
		{"v2.3.0", "v2.1.0", 1},
		{"v2.1.1", "v2.1.0", 1},
		{"v3.0.0", "v2.9.9", 1},
		{"v2.1.0-rc1", "v2.1.0", -1},
		{"v2.1.0-rc1", "v2.1.0-rc1", 0},
		{"v2.1.0-rc2", "v2.1.0-rc1", 1},
		{"v1.9.0", "v2.0.0", -1},
	}

	for _, tc := range tests {
		res := SemverCompare(tc.v1, tc.v2)
		if res != tc.expected {
			t.Errorf("SemverCompare(%q, %q) = %d; want %d", tc.v1, tc.v2, res, tc.expected)
		}
	}
}

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
		got := NormalizeArch(tc.input)
		if got != tc.expected {
			t.Errorf("NormalizeArch(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestFetchReleaseInfo(t *testing.T) {
	mockRelease := ReleaseInfo{
		TagName: "v2.2.0",
		Name:    "Fabric v2.2.0 Release",
		Assets: []ReleaseAsset{
			{Name: "fabric-linux-amd64", BrowserDownloadURL: "http://example.com/fabric-linux-amd64", Size: 1024},
			{Name: "fabric-linux-arm64", BrowserDownloadURL: "http://example.com/fabric-linux-arm64", Size: 1024},
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

	// 1. Success query
	info, err := FetchReleaseInfo(ctx, client, server.URL, "latest")
	if err != nil {
		t.Fatalf("FetchReleaseInfo failed: %v", err)
	}
	if info.TagName != "v2.2.0" {
		t.Errorf("expected tag 'v2.2.0', got %q", info.TagName)
	}
	if len(info.Assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(info.Assets))
	}

	// 2. 404 query
	_, err = FetchReleaseInfo(ctx, client, server.URL+"/releases/tags/v9.9.9", "v9.9.9")
	if err == nil {
		t.Errorf("expected error for 404 release, got nil")
	}
}

func TestRunUpdate_CheckOnly(t *testing.T) {
	mockRelease := ReleaseInfo{
		TagName: "v2.5.0",
		Name:    "Fabric v2.5.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRelease)
	}))
	defer server.Close()

	// 1. Check with older version (update available)
	var buf bytes.Buffer
	cfg := UpdaterConfig{
		CurrentVersion: "v2.1.0",
		ReleaseAPIURL:  server.URL,
		CheckOnly:      true,
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	if err := RunUpdate(cfg); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "An update is available: v2.1.0 -> v2.5.0") {
		t.Errorf("expected update available message, got:\n%s", out)
	}

	// 2. Check with same or newer version (up to date)
	buf.Reset()
	cfg.CurrentVersion = "v2.5.0"
	if err := RunUpdate(cfg); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "Fabric is already up to date (version v2.5.0)") {
		t.Errorf("expected up to date message, got:\n%s", out)
	}
}

func TestRunUpdate_EndToEnd(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-update-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create initial mock binaries
	oldFabric := filepath.Join(tmpDir, "fabric")
	oldServer := filepath.Join(tmpDir, "fabric-server")
	oldThread := filepath.Join(tmpDir, "fabric-thread")

	_ = os.WriteFile(oldFabric, []byte("OLD_CLI_BINARY"), 0755)
	_ = os.WriteFile(oldServer, []byte("OLD_SERVER_BINARY"), 0755)
	_ = os.WriteFile(oldThread, []byte("OLD_THREAD_BINARY"), 0755)

	newCliPayload := []byte("#!/bin/sh\necho 'NEW_CLI_v2.2.0'\n")
	newServerPayload := []byte("#!/bin/sh\necho 'NEW_SERVER_v2.2.0'\n")
	newThreadPayload := []byte("#!/bin/sh\necho 'NEW_THREAD_v2.2.0'\n")

	cliSum := sha256.Sum256(newCliPayload)
	serverSum := sha256.Sum256(newServerPayload)
	threadSum := sha256.Sum256(newThreadPayload)

	checksumsContent := fmt.Sprintf("%s  fabric-linux-amd64\n%s  fabric-server-linux-amd64\n%s  fabric-thread-linux-amd64\n",
		hex.EncodeToString(cliSum[:]),
		hex.EncodeToString(serverSum[:]),
		hex.EncodeToString(threadSum[:]),
	)

	// Setup mock server serving release metadata, downloads, and checksums
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/release":
			rel := ReleaseInfo{
				TagName: "v2.2.0",
				Name:    "Fabric v2.2.0",
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
	cfg := UpdaterConfig{
		CurrentVersion: "v2.1.0",
		ReleaseAPIURL:  server.URL + "/api/release",
		DownloadURL:    server.URL + "/downloads",
		InstallDir:     tmpDir,
		UpdateAll:      true,
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	if err := RunUpdate(cfg); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Successfully updated Fabric to v2.2.0!") {
		t.Errorf("expected success message in output, got:\n%s", out)
	}

	// Verify all binaries were upgraded
	cliContent, _ := os.ReadFile(oldFabric)
	if string(cliContent) != string(newCliPayload) {
		t.Errorf("fabric binary not updated properly: got %q", string(cliContent))
	}

	serverContent, _ := os.ReadFile(oldServer)
	if string(serverContent) != string(newServerPayload) {
		t.Errorf("fabric-server binary not updated properly: got %q", string(serverContent))
	}

	threadContent, _ := os.ReadFile(oldThread)
	if string(threadContent) != string(newThreadPayload) {
		t.Errorf("fabric-thread binary not updated properly: got %q", string(threadContent))
	}

	// Verify permissions
	info, _ := os.Stat(oldFabric)
	if info.Mode().Perm()&0111 == 0 {
		t.Errorf("updated binary does not have executable permissions: %v", info.Mode().Perm())
	}
}

func TestRunUpdate_AlreadyUpToDate_NoForce(t *testing.T) {
	mockRelease := ReleaseInfo{
		TagName: "v2.1.0",
		Name:    "Fabric v2.1.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRelease)
	}))
	defer server.Close()

	var buf bytes.Buffer
	cfg := UpdaterConfig{
		CurrentVersion: "v2.1.0",
		ReleaseAPIURL:  server.URL,
		Force:          false,
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	if err := RunUpdate(cfg); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Fabric is already up to date (version v2.1.0)") {
		t.Errorf("expected already up to date message, got:\n%s", out)
	}
}

func TestRunUpdate_ForceReinstall(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-force-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldFabric := filepath.Join(tmpDir, "fabric")
	_ = os.WriteFile(oldFabric, []byte("#!/bin/sh\necho ORIGINAL_CONTENT\n"), 0755)
	newPayload := []byte("#!/bin/sh\necho FORCED_REINSTALLED_CONTENT\n")
	newSum := sha256.Sum256(newPayload)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release":
			json.NewEncoder(w).Encode(ReleaseInfo{TagName: "v2.1.0"})
		case "/download/fabric-linux-amd64":
			w.Write(newPayload)
		case "/download/fabric-linux-amd64.sha256":
			w.Write([]byte(hex.EncodeToString(newSum[:]) + "  fabric-linux-amd64\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var buf bytes.Buffer
	cfg := UpdaterConfig{
		CurrentVersion: "v2.1.0",
		ReleaseAPIURL:  server.URL + "/release",
		DownloadURL:    server.URL + "/download",
		InstallDir:     tmpDir,
		Force:          true, // force update even if same version
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
		Out:            &buf,
	}

	if err := RunUpdate(cfg); err != nil {
		t.Fatalf("RunUpdate failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Successfully updated Fabric to v2.1.0!") {
		t.Errorf("expected success message, got:\n%s", out)
	}

	content, _ := os.ReadFile(oldFabric)
	if string(content) != string(newPayload) {
		t.Errorf("binary content mismatch: got %q, want %q", string(content), string(newPayload))
	}
}

func TestRunUpdate_ChecksumMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "fabric")
	_ = os.WriteFile(targetPath, []byte("ORIGINAL_BINARY"), 0755)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/release":
			json.NewEncoder(w).Encode(ReleaseInfo{TagName: "v2.5.0"})
		case "/downloads/fabric-linux-amd64":
			w.Write([]byte("TAMPERED_BINARY_PAYLOAD"))
		case "/downloads/checksums.txt":
			wrongHash := sha256.Sum256([]byte("DIFFERENT_PAYLOAD"))
			w.Write([]byte(fmt.Sprintf("%s  fabric-linux-amd64\n", hex.EncodeToString(wrongHash[:]))))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := UpdaterConfig{
		CurrentVersion: "v2.4.1",
		ReleaseAPIURL:  server.URL + "/api/release",
		DownloadURL:    server.URL + "/downloads",
		InstallDir:     tmpDir,
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
	}

	err := RunUpdate(cfg)
	if err == nil {
		t.Fatalf("expected RunUpdate to fail on checksum mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Original binary should not be replaced
	content, _ := os.ReadFile(targetPath)
	if string(content) != "ORIGINAL_BINARY" {
		t.Errorf("expected original binary to remain unmodified, got %q", string(content))
	}
}

func TestRunUpdate_MissingChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "fabric")
	_ = os.WriteFile(targetPath, []byte("ORIGINAL_BINARY"), 0755)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/release":
			json.NewEncoder(w).Encode(ReleaseInfo{TagName: "v2.5.0"})
		case "/downloads/fabric-linux-amd64":
			w.Write([]byte("BINARY_PAYLOAD_WITHOUT_CHECKSUM"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := UpdaterConfig{
		CurrentVersion: "v2.4.1",
		ReleaseAPIURL:  server.URL + "/api/release",
		DownloadURL:    server.URL + "/downloads",
		InstallDir:     tmpDir,
		OS:             "linux",
		Arch:           "amd64",
		HTTPClient:     server.Client(),
	}

	err := RunUpdate(cfg)
	if err == nil {
		t.Fatalf("expected RunUpdate to fail on missing checksum, got nil")
	}
	if !strings.Contains(err.Error(), "checksum manifest missing") && !strings.Contains(err.Error(), "checksum") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Original binary should remain unmodified
	content, _ := os.ReadFile(targetPath)
	if string(content) != "ORIGINAL_BINARY" {
		t.Errorf("expected original binary to remain unmodified, got %q", string(content))
	}
}

func TestUpdateCommand_Help(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"update", "--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "fabric update [flags]") {
		t.Errorf("expected update help output, got:\n%s", out)
	}
	if !strings.Contains(out, "--check") || !strings.Contains(out, "--force") {
		t.Errorf("expected flag definitions in help output, got:\n%s", out)
	}
}

