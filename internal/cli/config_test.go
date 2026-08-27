package cli

import (
	"os"
	"path/filepath"
	"testing"

	"fabric/internal/protocol"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary home directory
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")
	os.Setenv("FABRIC_SYS_CONFIG_DIR", tempHome)
	defer os.Unsetenv("FABRIC_SYS_CONFIG_DIR")

	// 1. Test Defaults
	cfg := LoadConfig("", "", "")
	if cfg.Host != "wss://localhost:8443/ws" {
		t.Errorf("expected default host, got %s", cfg.Host)
	}
	if cfg.Token != "default-secret" {
		t.Errorf("expected default token, got %s", cfg.Token)
	}

	// 2. Test Config File
	configDir := filepath.Join(tempHome, ".fabric")
	os.MkdirAll(configDir, 0755)
	configFile := filepath.Join(configDir, "config.json")
	os.WriteFile(configFile, []byte(`{"contexts": {"default": {"host": "wss://remote:8443/ws", "token": "file-secret", "ca_cert": "/etc/ca.crt"}}, "current_context": "default"}`), 0644)

	cfg = LoadConfig("", "", "")
	if cfg.Host != "wss://remote:8443/ws" {
		t.Errorf("expected file host, got %s", cfg.Host)
	}
	if cfg.Token != "file-secret" {
		t.Errorf("expected file token, got %s", cfg.Token)
	}
	if cfg.CACert != "/etc/ca.crt" {
		t.Errorf("expected file ca_cert, got %s", cfg.CACert)
	}

	// 3. Test Env Vars
	os.Setenv("FABRIC_HOST", "wss://env:8443/ws")
	os.Setenv("FABRIC_TOKEN", "env-secret")
	os.Setenv("FABRIC_CA_CERT", "/env/ca.crt")
	defer os.Unsetenv("FABRIC_HOST")
	defer os.Unsetenv("FABRIC_TOKEN")
	defer os.Unsetenv("FABRIC_CA_CERT")

	cfg = LoadConfig("", "", "")
	if cfg.Host != "wss://env:8443/ws" {
		t.Errorf("expected env host, got %s", cfg.Host)
	}
	if cfg.Token != "env-secret" {
		t.Errorf("expected env token, got %s", cfg.Token)
	}
	if cfg.CACert != "/env/ca.crt" {
		t.Errorf("expected env ca_cert, got %s", cfg.CACert)
	}

	// Test modern FABRIC_SERVER_URL precedence over FABRIC_SOCKET_URL and FABRIC_HOST
	os.Setenv("FABRIC_SOCKET_URL", "wss://socket-url:8443/ws")
	defer os.Unsetenv("FABRIC_SOCKET_URL")
	cfg = LoadConfig("", "", "")
	if cfg.Host != "wss://socket-url:8443/ws" {
		t.Errorf("expected FABRIC_SOCKET_URL over FABRIC_HOST, got %s", cfg.Host)
	}

	os.Setenv("FABRIC_SERVER_URL", "wss://server-url:8443/ws")
	defer os.Unsetenv("FABRIC_SERVER_URL")
	cfg = LoadConfig("", "", "")
	if cfg.Host != "wss://server-url:8443/ws" {
		t.Errorf("expected FABRIC_SERVER_URL precedence, got %s", cfg.Host)
	}

	// Test modern FABRIC_THREAD_NAME precedence over FABRIC_NODE_NAME
	os.Setenv("FABRIC_NODE_NAME", "legacy-node")
	defer os.Unsetenv("FABRIC_NODE_NAME")
	cfg = LoadConfig("", "", "")
	if cfg.ThreadName != "legacy-node" {
		t.Errorf("expected fallback to FABRIC_NODE_NAME, got %s", cfg.ThreadName)
	}

	os.Setenv("FABRIC_THREAD_NAME", "modern-thread")
	defer os.Unsetenv("FABRIC_THREAD_NAME")
	cfg = LoadConfig("", "", "")
	if cfg.ThreadName != "modern-thread" {
		t.Errorf("expected FABRIC_THREAD_NAME precedence, got %s", cfg.ThreadName)
	}

	// 4. Test Flags
	cfg = LoadConfig("wss://flag:8443/ws", "flag-secret", "", "/flag/ca.crt")
	if cfg.Host != "wss://flag:8443/ws" {
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

func TestRegisterInvertedIfApplicable(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// 1. Inverted node by status
	node := &protocol.NodeMetadata{
		Hostname: "my-edge-server",
		Status:   "online [MODE: inverted]",
		Tags:     []string{"edge"},
	}

	registerInvertedIfApplicable("root@10.0.0.50", "8443", node)

	entryHost, okHost := LookupDirectNode("my-edge-server")
	if !okHost {
		t.Fatalf("expected hostname 'my-edge-server' to be registered")
	}
	if entryHost.Address != "10.0.0.50:8443" {
		t.Errorf("expected address 10.0.0.50:8443, got: %s", entryHost.Address)
	}

	entryIP, okIP := LookupDirectNode("10.0.0.50")
	if !okIP {
		t.Fatalf("expected target host '10.0.0.50' to also be registered")
	}
	if entryIP.Address != "10.0.0.50:8443" {
		t.Errorf("expected address 10.0.0.50:8443, got: %s", entryIP.Address)
	}
}


