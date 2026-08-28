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

func TestEmptyJSONLists_ArrayBrackets(t *testing.T) {
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

	// 1. thread ls --json on empty mesh
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "ls", "--json"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("thread ls --json failed: %v", err)
		}
		out := strings.TrimSpace(stdoutBuf.String())
		if out != "[]" {
			t.Errorf("expected '[]' for empty thread ls --json, got %q", out)
		}
	}

	// 2. device ls --json on empty devices
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"device", "ls", "--json"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("device ls --json failed: %v", err)
		}
		out := strings.TrimSpace(stdoutBuf.String())
		if out != "[]" {
			t.Errorf("expected '[]' for empty device ls --json, got %q", out)
		}
	}

	// 3. peer ls --format json on empty peers
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"peer", "ls", "--format", "json"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("peer ls --format json failed: %v", err)
		}
		out := strings.TrimSpace(stdoutBuf.String())
		if out != "[]" {
			t.Errorf("expected '[]' for empty peer ls --format json, got %q", out)
		}
	}
}

func TestInitFlagValidation_InvalidRole(t *testing.T) {
	// Should fail immediately with validation error without demanding root
	rootCmd.SetArgs([]string{"init", "--role", "invalid_role_name"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error for invalid role, got nil")
	}
	if !strings.Contains(err.Error(), "invalid role") {
		t.Errorf("expected error message mentioning 'invalid role', got %v", err)
	}

	// Invalid mode should also fail immediately
	rootCmd.SetArgs([]string{"init", "--role", "thread", "--mode", "invalid_mode"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error for invalid mode, got nil")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("expected error message mentioning 'invalid mode', got %v", err)
	}
}

func TestFormatError_ExitCode(t *testing.T) {
	exitErr := &ExitCodeError{Code: 42}
	if exitErr.ExitCode() != 42 {
		t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
	}
	if exitErr.Error() != "exit code 42" {
		t.Errorf("expected 'exit code 42', got %q", exitErr.Error())
	}
}

func TestFormatRoleDisplay_CLI(t *testing.T) {
	got := formatRoleDisplay("cli", "local")
	if got != "CLI (Operator)" {
		t.Errorf("expected 'CLI (Operator)', got %q", got)
	}
}

func TestRootCmdHelp_NoEmptyDeprecatedGroup(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	if err := rootCmd.Help(); err != nil {
		t.Fatalf("rootCmd.Help() failed: %v", err)
	}
	helpText := buf.String()
	if strings.Contains(helpText, "Cluster & Node Commands (Deprecated):") {
		t.Errorf("help output contains empty deprecated commands header:\n%s", helpText)
	}
}

func TestPeerLs_EmptyStateMessage(t *testing.T) {
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

	var stdoutBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetArgs([]string{"peer", "ls"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("peer ls failed: %v", err)
	}
	out := stdoutBuf.String()
	if !strings.Contains(out, "No server federation peers connected.") {
		t.Errorf("expected friendly empty state message, got:\n%s", out)
	}
}

func TestLoadConfig_UnreadableCACertFallback(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("FABRIC_SYS_CONFIG_DIR", tempHome)

	// Create a dummy config pointing to an unreadable/non-existent path
	cfg := &Config{
		Host:   "wss://localhost:8443/ws",
		Token:  "test-secret",
		CACert: "/root/.fabric/ca.crt",
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded := LoadConfig("", "", "")
	if loaded.CACert != "" {
		t.Errorf("expected empty CACert for unreadable CA path, got %q", loaded.CACert)
	}
}




