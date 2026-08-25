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
