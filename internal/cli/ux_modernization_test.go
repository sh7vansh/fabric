package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"
)

func TestFormatHelpers(t *testing.T) {
	// Platform format
	if got := FormatPlatform("linux", "amd64"); got != "linux/amd64" {
		t.Errorf("expected linux/amd64, got %q", got)
	}
	if got := FormatPlatform("darwin", ""); got != "darwin" {
		t.Errorf("expected darwin, got %q", got)
	}
	if got := FormatPlatform("", "arm64"); got != "arm64" {
		t.Errorf("expected arm64, got %q", got)
	}
	if got := FormatPlatform("", ""); got != "-" {
		t.Errorf("expected -, got %q", got)
	}

	// Relative time format
	if got := FormatRelativeTime(time.Time{}); got != "never" {
		t.Errorf("expected 'never' for zero time, got %q", got)
	}
	if got := FormatRelativeTime(time.Now().Add(-10 * time.Second)); !strings.HasSuffix(got, "s ago") {
		t.Errorf("expected relative seconds, got %q", got)
	}
}

func TestFormatError_ConnectionRefused(t *testing.T) {
	fakeErr := &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18443},
		Err:  errors.New("connect: connection refused"),
	}

	formatted := FormatError(fakeErr)
	if strings.Contains(formatted, "fabric thread service status") {
		t.Errorf("connection refused tip should not reference fabric thread service status, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "Check if fabric-server is active") {
		t.Errorf("expected server check tip, got:\n%s", formatted)
	}
}

func TestEmptyStatesAndJSONFlags(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("FABRIC_SYS_CONFIG_DIR", tempHome)

	ts, r := setupTestMesh(t)
	defer ts.Close()
	defer r.Close()

	caCertFlag = filepath.Join(tempHome, ".fabric", "ca.crt")
	serverFlag = ts.URL
	tokenFlag = "test-token-thread"
	defer func() {
		serverFlag = ""
		tokenFlag = ""
		caCertFlag = ""
	}()

	// 1. fabric ps empty state
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"ps"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("ps failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "No active threads connected to the Fabric.") {
			t.Errorf("expected exact empty state 'No active threads connected to the Fabric.', got:\n%s", out)
		}
		if strings.Contains(out, "compute threads") {
			t.Errorf("must not use non-canonical 'compute threads', got:\n%s", out)
		}
	}

	// 2. fabric device ls empty state
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"device", "ls"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("device ls failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "No WireGuard devices paired.") {
			t.Errorf("expected exact empty state 'No WireGuard devices paired.', got:\n%s", out)
		}
	}

	// Register a test thread and verify --json flag
	r.RegisterThread(protocol.ThreadMetadata{
		ID:          "worker-qa",
		Hostname:    "worker-qa",
		RemoteIP:    "10.0.0.5",
		Status:      "online",
		OS:          "linux",
		Arch:        "amd64",
		ConnectedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil)

	// 3. fabric thread inspect --json
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "inspect", "--json", "worker-qa"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("thread inspect --json failed: %v", err)
		}
		var list []protocol.ThreadMetadata
		if err := json.Unmarshal(stdoutBuf.Bytes(), &list); err != nil {
			t.Fatalf("failed to parse JSON from --json flag: %v\nOutput was:\n%s", err, stdoutBuf.String())
		}
		if len(list) != 1 || list[0].Hostname != "worker-qa" {
			t.Errorf("unexpected inspect JSON: %+v", list)
		}
	}

	// 4. fabric thread ls --json
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "ls", "--json"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("thread ls --json failed: %v", err)
		}
		var list []protocol.ThreadMetadata
		if err := json.Unmarshal(stdoutBuf.Bytes(), &list); err != nil {
			t.Fatalf("failed to parse JSON from thread ls --json: %v\nOutput was:\n%s", err, stdoutBuf.String())
		}
		if len(list) != 1 || list[0].Hostname != "worker-qa" {
			t.Errorf("unexpected thread ls JSON: %+v", list)
		}
	}
}
