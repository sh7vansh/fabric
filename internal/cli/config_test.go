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
	cfg := LoadConfig("", "", "")
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
	os.WriteFile(configFile, []byte(`{"contexts": {"default": {"host": "ws://remote:8080/ws", "token": "file-secret", "ca_cert": "/etc/ca.crt"}}, "current_context": "default"}`), 0644)

	cfg = LoadConfig("", "", "")
	if cfg.Host != "ws://remote:8080/ws" {
		t.Errorf("expected file host, got %s", cfg.Host)
	}
	if cfg.Token != "file-secret" {
		t.Errorf("expected file token, got %s", cfg.Token)
	}
	if cfg.CACert != "/etc/ca.crt" {
		t.Errorf("expected file ca_cert, got %s", cfg.CACert)
	}

	// 3. Test Env Vars
	os.Setenv("FABRIC_HOST", "ws://env:8080/ws")
	os.Setenv("FABRIC_TOKEN", "env-secret")
	os.Setenv("FABRIC_CA_CERT", "/env/ca.crt")
	defer os.Unsetenv("FABRIC_HOST")
	defer os.Unsetenv("FABRIC_TOKEN")
	defer os.Unsetenv("FABRIC_CA_CERT")

	cfg = LoadConfig("", "", "")
	if cfg.Host != "ws://env:8080/ws" {
		t.Errorf("expected env host, got %s", cfg.Host)
	}
	if cfg.Token != "env-secret" {
		t.Errorf("expected env token, got %s", cfg.Token)
	}
	if cfg.CACert != "/env/ca.crt" {
		t.Errorf("expected env ca_cert, got %s", cfg.CACert)
	}

	// 4. Test Flags
	cfg = LoadConfig("ws://flag:8080/ws", "flag-secret", "", "/flag/ca.crt")
	if cfg.Host != "ws://flag:8080/ws" {
		t.Errorf("expected flag host, got %s", cfg.Host)
	}
	if cfg.Token != "flag-secret" {
		t.Errorf("expected flag token, got %s", cfg.Token)
	}
	if cfg.CACert != "/flag/ca.crt" {
		t.Errorf("expected flag ca_cert, got %s", cfg.CACert)
	}
}

func TestDirectNodeRegistry(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// Register a direct node
	err := RegisterDirectNode("edge-1", "192.168.1.99:8443", []string{"gateway"})
	if err != nil {
		t.Fatalf("RegisterDirectNode failed: %v", err)
	}

	// Lookup direct node
	entry, ok := LookupDirectNode("edge-1")
	if !ok {
		t.Fatalf("LookupDirectNode failed to find registered node 'edge-1'")
	}
	if entry.Address != "192.168.1.99:8443" {
		t.Errorf("expected address 192.168.1.99:8443, got %s", entry.Address)
	}
	hasInverted := false
	for _, tag := range entry.Tags {
		if tag == "inverted" {
			hasInverted = true
		}
	}
	if !hasInverted {
		t.Errorf("expected 'inverted' tag in entry: %v", entry.Tags)
	}

	// Reload config from disk
	cfg := LoadConfig("", "", "")
	if len(cfg.DirectNodes) != 1 {
		t.Fatalf("expected 1 direct node in loaded config, got %d", len(cfg.DirectNodes))
	}
	if cfg.DirectNodes["edge-1"].Address != "192.168.1.99:8443" {
		t.Errorf("expected 192.168.1.99:8443 in loaded config, got %s", cfg.DirectNodes["edge-1"].Address)
	}
}

