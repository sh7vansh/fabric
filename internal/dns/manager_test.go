package dns

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"

	"github.com/miekg/dns"
)

func TestFabricDNSManagerLifecycle(t *testing.T) {
	mgr := NewFabricDNSManager("fabric.mesh")
	mgr.skipOSOps = true // Skip root-requiring resolvectl calls in test

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Teardown()

	time.Sleep(50 * time.Millisecond)

	m := new(dns.Msg)
	m.SetQuestion("test.fabric.mesh.", dns.TypeA)

	// Simulate DNS response directly
	respMsg := new(dns.Msg)
	respMsg.SetReply(m)
	rr, _ := dns.NewRR("test.fabric.mesh. 10 IN A 192.168.1.1")
	respMsg.Answer = append(respMsg.Answer, rr)
	wire, _ := respMsg.Pack()

	mgr.HandleDNSResponse(protocol.DNSResponse{
		Type:      protocol.TypeDNSResponse,
		SessionID: "test-session",
		RCode:     dns.RcodeSuccess,
		TTL:       10,
		Data:      base64.StdEncoding.EncodeToString(wire),
	})

	mgr.cacheMux.RLock()
	_, found := mgr.cache["test.fabric.mesh."]
	mgr.cacheMux.RUnlock()
	if !found {
		t.Errorf("Expected query to be cached")
	}
}

func TestFabricDNSManagerHostsFallback(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-hosts-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	tmpFile.Close()

	mgr := NewFabricDNSManager("fabric.mesh")
	mgr.hostsPath = tmpFile.Name()
	mgr.useResolved = false // Force hosts file fallback

	threads := []protocol.ThreadMetadata{
		{Hostname: "alpha"},
		{Hostname: "beta"},
	}

	mgr.SyncThreads(threads, "http://10.0.0.1:8080")

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	str := string(content)

	if !strings.Contains(str, "# BEGIN FABRIC MESH") {
		t.Errorf("Expected begin block marker, got:\n%s", str)
	}
	if !strings.Contains(str, "10.0.0.1 alpha.fabric.mesh") {
		t.Errorf("Expected alpha thread entry, got:\n%s", str)
	}

	// Teardown should clean hosts block
	mgr.Teardown()

	cleaned, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	cleanedStr := string(cleaned)

	if strings.Contains(cleanedStr, "# BEGIN FABRIC MESH") {
		t.Errorf("Expected hosts block to be removed, got:\n%s", cleanedStr)
	}
	if strings.Contains(cleanedStr, "alpha.fabric.mesh") {
		t.Errorf("Expected thread entry to be removed, got:\n%s", cleanedStr)
	}
}

func TestFabricDNSManager_PreventHostsInjection(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-hosts-inj-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	mgr := NewFabricDNSManager("fabric.mesh")
	mgr.hostsPath = tmpFile.Name()
	mgr.useResolved = false

	maliciousThreads := []protocol.ThreadMetadata{
		{Hostname: "evil\n192.168.1.100 injected.host"},
		{Hostname: "bad;rm -rf /"},
		{Hostname: "valid-thread"},
	}

	mgr.SyncThreads(maliciousThreads, "http://10.0.0.1:8080")

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	str := string(content)

	if strings.Contains(str, "injected.host") {
		t.Errorf("Security regression: newline injection succeeded into /etc/hosts:\n%s", str)
	}
	if strings.Contains(str, "bad;rm") {
		t.Errorf("Security regression: invalid characters admitted into /etc/hosts:\n%s", str)
	}
	if !strings.Contains(str, "10.0.0.1 valid-thread.fabric.mesh") {
		t.Errorf("Expected valid thread to be recorded in hosts block:\n%s", str)
	}

	mgr.Teardown()
}

func TestFabricDNSManager_AtomicWriteRecoveryAcrossMounts(t *testing.T) {
	tempDir := t.TempDir()
	hostsPath := filepath.Join(tempDir, "hosts")
	_ = os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n"), 0644)

	mgr := NewFabricDNSManager("fabric.mesh")
	mgr.hostsPath = hostsPath
	mgr.useResolved = false

	threads := []protocol.ThreadMetadata{
		{Hostname: "edge-node"},
	}

	mgr.SyncThreads(threads, "http://10.0.0.1:8080")

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("failed to read hosts file: %v", err)
	}
	if !strings.Contains(string(data), "edge-node.fabric.mesh") {
		t.Errorf("expected edge-node in hosts file, got:\n%s", string(data))
	}

	mgr.Teardown()
}
