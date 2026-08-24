package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary home directory
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// 1. Test Defaults
	cfg := LoadConfig("", "")
	if cfg.Host != "ws://localhost:8080/ws" {
		t.Errorf("expected default host, got %s", cfg.Host)
	}
	if cfg.Token != "default-secret" {
		t.Errorf("expected default token, got %s", cfg.Token)
	}

	// 2. Test Config File
	configDir := filepath.Join(tempHome, ".fabric")
	os.MkdirAll(configDir, 0755)
	configFile := filepath.Join(configDir, "config.json")
	os.WriteFile(configFile, []byte(`{"contexts": {"default": {"host": "ws://remote:8080/ws", "token": "file-secret"}}, "current_context": "default"}`), 0644)

	cfg = LoadConfig("", "")
	if cfg.Host != "ws://remote:8080/ws" {
		t.Errorf("expected file host, got %s", cfg.Host)
	}
	if cfg.Token != "file-secret" {
		t.Errorf("expected file token, got %s", cfg.Token)
	}

	// 3. Test Env Vars
	os.Setenv("FABRIC_HOST", "ws://env:8080/ws")
	os.Setenv("FABRIC_TOKEN", "env-secret")
	defer os.Unsetenv("FABRIC_HOST")
	defer os.Unsetenv("FABRIC_TOKEN")

	cfg = LoadConfig("", "")
	if cfg.Host != "ws://env:8080/ws" {
		t.Errorf("expected env host, got %s", cfg.Host)
	}
	if cfg.Token != "env-secret" {
		t.Errorf("expected env token, got %s", cfg.Token)
	}

	// 4. Test Flags
	cfg = LoadConfig("ws://flag:8080/ws", "flag-secret")
	if cfg.Host != "ws://flag:8080/ws" {
		t.Errorf("expected flag host, got %s", cfg.Host)
	}
	if cfg.Token != "flag-secret" {
		t.Errorf("expected flag token, got %s", cfg.Token)
	}
}
