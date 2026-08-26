package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitAndAgentCommands(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	// 1. Test `fabric init` non-interactively
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"init", "-y", "--server", "wss://test-gw:8443/ws", "--token", "custom-secret", "--domain", "fabric.mesh"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric init failed: %v", err)
		}

		// Verify written config.json
		cfgPath := filepath.Join(tempHome, ".fabric", "config.json")
		if _, err := os.Stat(cfgPath); err != nil {
			t.Fatalf("config.json not created at %s", cfgPath)
		}

		cfg := LoadConfig("", "", "")
		if cfg.Host != "wss://test-gw:8443/ws" {
			t.Errorf("expected host 'wss://test-gw:8443/ws', got %s", cfg.Host)
		}
		if cfg.Token != "custom-secret" {
			t.Errorf("expected token 'custom-secret', got %s", cfg.Token)
		}
	}

	// 2. Test `fabric setup` legacy alias with deprecation warning
	{
		stderrBuf.Reset()
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"setup", "-y", "--server", "wss://setup-gw:8443/ws", "--token", "setup-secret"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric setup failed: %v", err)
		}

		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric setup' is deprecated. Use 'fabric init' instead.") {
			t.Errorf("expected deprecation warning for setup, got: %s", stderrBuf.String())
		}

		cfg := LoadConfig("", "", "")
		if cfg.Host != "wss://setup-gw:8443/ws" {
			t.Errorf("expected host updated to 'wss://setup-gw:8443/ws', got %s", cfg.Host)
		}
	}

	// 3. Test `fabric service status` legacy alias deprecation warning
	{
		stderrBuf.Reset()
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"service", "status"})

		_ = rootCmd.Execute()

		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric service' is deprecated. Use 'fabric thread service' instead.") {
			t.Errorf("expected deprecation warning for service status, got: %s", stderrBuf.String())
		}
	}

	// 4. Test `fabric agent status` legacy alias deprecation warning
	{
		stderrBuf.Reset()
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"agent", "status"})

		_ = rootCmd.Execute()

		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric agent' is deprecated. Use 'fabric thread service' instead.") {
			t.Errorf("expected deprecation warning for agent status, got: %s", stderrBuf.String())
		}
	}

	// 5. Test `fabric thread service status`
	{
		stderrBuf.Reset()
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"thread", "service", "status"})

		_ = rootCmd.Execute()
		// Should not produce deprecation warning
		if strings.Contains(stderrBuf.String(), "deprecated") {
			t.Errorf("unexpected deprecation warning for thread service: %s", stderrBuf.String())
		}
	}
}

func TestParseRoleChoice(t *testing.T) {
	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	tests := []struct {
		input    string
		expected string
	}{
		{"1", "thread"},
		{"thread", "thread"},
		{"THREAD", "thread"},
		{"2", "server"},
		{"server", "server"},
		{"3", "both"},
		{"both", "both"},
		{"agent", "thread"},
		{"cli", "cli"},
		{"client", "cli"},
		{"", "thread"},
		{"invalid", "thread"},
	}

	for _, tt := range tests {
		got := parseRoleChoice(tt.input)
		if got != tt.expected {
			t.Errorf("parseRoleChoice(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestInitRoleEnvGeneration(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// Test init with --role=both and --mode=remote non-interactively
	var stdoutBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetArgs([]string{"init", "-y", "--role", "both", "--mode", "remote", "--server", "wss://localhost:8443/ws", "--token", "both-secret", "--domain", "fabric.mesh"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("fabric init with --role both failed: %v", err)
	}

	serverEnv := filepath.Join(tempHome, ".fabric", "server.env")
	if data, err := os.ReadFile(serverEnv); err != nil {
		t.Errorf("expected server.env at %s, error: %v", serverEnv, err)
	} else {
		content := string(data)
		if !strings.Contains(content, "FABRIC_TOKEN=both-secret") || !strings.Contains(content, "FABRIC_DOMAIN=fabric.mesh") || !strings.Contains(content, "FABRIC_PORT=8443") {
			t.Errorf("unexpected server.env content (missing FABRIC_PORT=8443): %s", content)
		}
		if strings.Contains(content, "8080") {
			t.Errorf("server.env should not contain legacy 8080: %s", content)
		}
	}

	threadEnv := filepath.Join(tempHome, ".fabric", "thread.env")
	if data, err := os.ReadFile(threadEnv); err != nil {
		t.Errorf("expected thread.env at %s, error: %v", threadEnv, err)
	} else {
		content := string(data)
		if !strings.Contains(content, "FABRIC_SERVER_URL=wss://localhost:8443/ws") ||
			!strings.Contains(content, "FABRIC_MODE=remote") ||
			!strings.Contains(content, "FABRIC_LISTEN=:8443") ||
			!strings.Contains(content, "FABRIC_TOKEN=both-secret") {
			t.Errorf("unexpected thread.env content: %s", content)
		}
	}
}

func TestInitRoleAgentDeprecation(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	var stdoutBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetErr(&stderrBuf)
	rootCmd.SetArgs([]string{"init", "-y", "--role", "agent", "--server", "wss://localhost:8443/ws", "--token", "agent-secret"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("fabric init with --role agent failed: %v", err)
	}

	if !strings.Contains(stderrBuf.String(), "Warning: '--role=agent' is deprecated. Use '--role=thread' instead.") {
		t.Errorf("expected deprecation warning for --role=agent, got: %s", stderrBuf.String())
	}

	threadEnv := filepath.Join(tempHome, ".fabric", "thread.env")
	if _, err := os.Stat(threadEnv); err != nil {
		t.Errorf("expected thread.env at %s, error: %v", threadEnv, err)
	}
}

func TestInitServerCABootstrapFailure(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	// Point CA dir to an invalid path that cannot be created
	t.Setenv("FABRIC_CA_DIR", "/dev/null/cannot_create_dir")

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetErr(&stderrBuf)
	rootCmd.SetArgs([]string{"init", "-y", "--role", "server", "--token", "test-token"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected fabric init to fail when CA bootstrapping fails, got nil error")
	}
	if !strings.Contains(err.Error(), "failed to bootstrap Certificate Authority") {
		t.Errorf("expected clear CA bootstrapping error message, got: %v", err)
	}
}

func TestInitServerCABootstrapSuccess(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetErr(&stderrBuf)
	rootCmd.SetArgs([]string{"init", "-y", "--role", "server", "--token", "test-token", "--domain", "test.mesh"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("fabric init server failed: %v", err)
	}

	caCert := filepath.Join(tempHome, ".fabric", "ca", "ca.crt")
	if _, err := os.Stat(caCert); err != nil {
		t.Errorf("expected ca.crt to be created at %s, got err: %v", caCert, err)
	}
}

func TestInitTrustCA_FailureWhenNoCAFound(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("FABRIC_CA_DIR", filepath.Join(tempHome, "nonexistent-ca"))
	t.Setenv("FABRIC_CA_CERT", filepath.Join(tempHome, "nonexistent-ca.crt"))

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetErr(&stderrBuf)
	rootCmd.SetArgs([]string{"init", "--trust-ca"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected fabric init --trust-ca to fail when no CA is found")
	}
	if !strings.Contains(err.Error(), "could not find Root CA") && !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("expected CA not found error, got: %v", err)
	}
}

func TestInitSudoUserSync(t *testing.T) {
	rootHome := t.TempDir()
	userHome := t.TempDir()

	t.Setenv("HOME", rootHome)
	t.Setenv("SUDO_USER", "testuser")
	t.Setenv("SUDO_HOME", userHome)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetErr(&stderrBuf)
	rootCmd.SetArgs([]string{"init", "-y", "--role", "both", "--token", "shared-secret-tok", "--domain", "sync.mesh"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("fabric init under sudo failed: %v", err)
	}

	// Verify user's ~/.fabric/config.json was populated with the token
	userCfgPath := filepath.Join(userHome, ".fabric", "config.json")
	if _, err := os.Stat(userCfgPath); err != nil {
		t.Fatalf("expected config.json at %s, got: %v", userCfgPath, err)
	}

	// Verify LoadConfig from user's perspective picks up the token
	t.Setenv("HOME", userHome)
	t.Setenv("SUDO_USER", "")
	t.Setenv("SUDO_HOME", "")

	cfg := LoadConfig("", "", "")
	if cfg.Token != "shared-secret-tok" {
		t.Errorf("expected user cfg token %q, got %q", "shared-secret-tok", cfg.Token)
	}
}
