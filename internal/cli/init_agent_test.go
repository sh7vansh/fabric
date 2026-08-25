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
		rootCmd.SetArgs([]string{"init", "-y", "--server", "ws://test-gw:8080/ws", "--token", "custom-secret", "--domain", "fabric.mesh"})

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
		if cfg.Host != "ws://test-gw:8080/ws" {
			t.Errorf("expected host 'ws://test-gw:8080/ws', got %s", cfg.Host)
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
		rootCmd.SetArgs([]string{"setup", "-y", "--server", "ws://setup-gw:8080/ws", "--token", "setup-secret"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric setup failed: %v", err)
		}

		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric setup' is deprecated. Use 'fabric init' instead.") {
			t.Errorf("expected deprecation warning for setup, got: %s", stderrBuf.String())
		}

		cfg := LoadConfig("", "", "")
		if cfg.Host != "ws://setup-gw:8080/ws" {
			t.Errorf("expected host updated to 'ws://setup-gw:8080/ws', got %s", cfg.Host)
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

		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric service' is deprecated. Use 'fabric agent' instead.") {
			t.Errorf("expected deprecation warning for service status, got: %s", stderrBuf.String())
		}
	}
}

func TestParseRoleChoice(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1", "client"},
		{"client", "client"},
		{"CLIENT", "client"},
		{"2", "server"},
		{"server", "server"},
		{"3", "agent"},
		{"agent", "agent"},
		{"4", "both"},
		{"both", "both"},
		{"", "client"},
		{"invalid", "client"},
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

	// Test init with --role=both non-interactively
	var stdoutBuf bytes.Buffer
	rootCmd.SetOut(&stdoutBuf)
	rootCmd.SetArgs([]string{"init", "-y", "--role", "both", "--server", "ws://localhost:8080/ws", "--token", "both-secret", "--domain", "fabric.mesh"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("fabric init with --role both failed: %v", err)
	}

	serverEnv := filepath.Join(tempHome, ".fabric", "server.env")
	if data, err := os.ReadFile(serverEnv); err != nil {
		t.Errorf("expected server.env at %s, error: %v", serverEnv, err)
	} else {
		content := string(data)
		if !strings.Contains(content, "FABRIC_TOKEN=both-secret") || !strings.Contains(content, "FABRIC_DOMAIN=fabric.mesh") {
			t.Errorf("unexpected server.env content: %s", content)
		}
	}

	agentEnv := filepath.Join(tempHome, ".fabric", "agent.env")
	if data, err := os.ReadFile(agentEnv); err != nil {
		t.Errorf("expected agent.env at %s, error: %v", agentEnv, err)
	} else {
		content := string(data)
		if !strings.Contains(content, "FABRIC_SERVER_URL=ws://localhost:8080/ws") || !strings.Contains(content, "FABRIC_TOKEN=both-secret") {
			t.Errorf("unexpected agent.env content: %s", content)
		}
	}
}
