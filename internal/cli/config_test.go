package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestDirectThreadRegistry(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// Register a direct thread using canonical method
	err := RegisterDirectThread("edge-1", "192.168.1.99:8443", []string{"gateway"})
	if err != nil {
		t.Fatalf("RegisterDirectThread failed: %v", err)
	}

	// Lookup direct thread
	entry, ok := LookupDirectThread("edge-1")
	if !ok {
		t.Fatalf("LookupDirectThread failed to find registered thread 'edge-1'")
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

	// Test backward-compatible lookup alias
	entryAlias, okAlias := LookupDirectNode("edge-1")
	if !okAlias || entryAlias.Address != "192.168.1.99:8443" {
		t.Errorf("expected LookupDirectNode to return registered entry")
	}

	// Reload config from disk
	cfg := LoadConfig("", "", "")
	if len(cfg.DirectThreads) != 1 {
		t.Fatalf("expected 1 direct thread in loaded config, got %d", len(cfg.DirectThreads))
	}
	if cfg.DirectThreads["edge-1"].Address != "192.168.1.99:8443" {
		t.Errorf("expected 192.168.1.99:8443 in loaded config, got %s", cfg.DirectThreads["edge-1"].Address)
	}
}

func TestDirectThreadsJSONBackwardCompatibility(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// Create legacy config file containing direct_nodes
	configDir := filepath.Join(tempHome, ".fabric")
	os.MkdirAll(configDir, 0755)
	configFile := filepath.Join(configDir, "config.json")
	legacyJSON := `{
		"current_context": "default",
		"contexts": {
			"default": {
				"host": "wss://remote:8443/ws",
				"token": "file-secret",
				"direct_nodes": {
					"legacy-edge": {
						"address": "10.10.0.5:8443",
						"tags": ["remote", "edge"]
					}
				}
			}
		},
		"direct_nodes": {
			"global-legacy-edge": {
				"address": "10.10.0.6:8443",
				"tags": ["remote"]
			}
		}
	}`
	if err := os.WriteFile(configFile, []byte(legacyJSON), 0644); err != nil {
		t.Fatalf("failed to write legacy config: %v", err)
	}

	cfg := LoadConfig("", "", "")
	if len(cfg.DirectThreads) != 2 {
		t.Fatalf("expected 2 direct threads loaded from legacy direct_nodes, got %d", len(cfg.DirectThreads))
	}
	if cfg.DirectThreads["legacy-edge"].Address != "10.10.0.5:8443" {
		t.Errorf("expected legacy-edge address 10.10.0.5:8443, got %s", cfg.DirectThreads["legacy-edge"].Address)
	}
	if cfg.DirectThreads["global-legacy-edge"].Address != "10.10.0.6:8443" {
		t.Errorf("expected global-legacy-edge address 10.10.0.6:8443, got %s", cfg.DirectThreads["global-legacy-edge"].Address)
	}

	// Persisting config should write direct_threads cleanly
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	savedBytes, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read saved config: %v", err)
	}
	if !strings.Contains(string(savedBytes), `"direct_threads"`) {
		t.Errorf("expected saved config to contain direct_threads key: %s", string(savedBytes))
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

func TestConfigCommand(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	// 1. fabric config set default_server
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stdoutBuf)
		rootCmd.SetArgs([]string{"config", "set", "default_server", "wss://control.fabric.internal:8443/ws"})
		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("config set default_server failed: %v", err)
		}
	}

	// 2. fabric config get default_server
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stdoutBuf)
		rootCmd.SetArgs([]string{"config", "get", "default_server"})
		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("config get default_server failed: %v", err)
		}
		if !strings.Contains(stdoutBuf.String(), "wss://control.fabric.internal:8443/ws") {
			t.Errorf("expected wss://control.fabric.internal:8443/ws, got: %s", stdoutBuf.String())
		}
	}

	// 3. fabric config set format
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stdoutBuf)
		rootCmd.SetArgs([]string{"config", "set", "format", "json"})
		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("config set format failed: %v", err)
		}
	}

	// 4. fabric config get format
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stdoutBuf)
		rootCmd.SetArgs([]string{"config", "get", "format"})
		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("config get format failed: %v", err)
		}
		if !strings.Contains(stdoutBuf.String(), "json") {
			t.Errorf("expected json, got: %s", stdoutBuf.String())
		}
	}

	// 5. fabric config view
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stdoutBuf)
		rootCmd.SetArgs([]string{"config", "view"})
		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("config view failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "control.fabric.internal") {
			t.Errorf("expected view to contain control.fabric.internal, got: %s", out)
		}
	}
}

func TestThreadRegistryDetailed(t *testing.T) {
	reg := NewThreadRegistry()
	reg.Set("Worker-Alpha", DirectThreadEntry{
		Address:  "192.168.1.50:8443",
		Hostname: "worker-alpha",
		Domain:   "fabric.mesh",
		Tags:     []string{"gpu", "remote", "prod"},
	})
	reg.Set("DB-Node", DirectThreadEntry{
		Address:  "192.168.1.60:8443",
		Hostname: "db-1",
		Domain:   "fabric.mesh",
		Tags:     []string{"database", "remote"},
	})

	// 1. Case-insensitive key lookup
	entry, ok := reg.Get("worker-alpha")
	if !ok || entry.Address != "192.168.1.50:8443" {
		t.Fatalf("expected to find worker-alpha case-insensitively, got %v", entry)
	}

	// 2. FQDN lookup
	entryFQDN, okFQDN := reg.Get("db-1.fabric.mesh")
	if !okFQDN || entryFQDN.Address != "192.168.1.60:8443" {
		t.Fatalf("expected to find db-1 via FQDN, got %v", entryFQDN)
	}

	// 3. Tag search
	gpuNodes := reg.FindByTag("gpu")
	if len(gpuNodes) != 1 || gpuNodes[0].Hostname != "worker-alpha" {
		t.Errorf("expected 1 gpu node, got %d", len(gpuNodes))
	}
	dbNodes := reg.FindByTag("database")
	if len(dbNodes) != 1 || dbNodes[0].Hostname != "db-1" {
		t.Errorf("expected 1 db node, got %d", len(dbNodes))
	}

	// 4. Concurrent access safety
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			reg.Set(fmt.Sprintf("node-%d", idx), DirectThreadEntry{
				Address:  fmt.Sprintf("10.0.0.%d:8443", idx),
				Hostname: fmt.Sprintf("node-%d", idx),
				Tags:     []string{"worker"},
			})
		}(i)
		go func(idx int) {
			defer wg.Done()
			_, _ = reg.Get("worker-alpha")
			_ = reg.FindByTag("worker")
			_ = reg.List()
		}(i)
	}
	wg.Wait()

	if reg.Len() < 20 {
		t.Errorf("expected at least 20 entries, got %d", reg.Len())
	}
}



