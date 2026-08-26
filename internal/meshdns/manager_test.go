package meshdns

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"

	"github.com/miekg/dns"
)

func TestSystemDNSManagerLifecycle(t *testing.T) {
	mgr := NewSystemDNSManager("fabric.mesh")
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

func TestSystemDNSManagerHostsFallback(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-hosts-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	tmpFile.Close()

	mgr := NewSystemDNSManager("fabric.mesh")
	mgr.hostsPath = tmpFile.Name()
	mgr.useResolved = false // Force hosts file fallback

	nodes := []protocol.NodeMetadata{
		{Hostname: "alpha"},
		{Hostname: "beta"},
	}

	mgr.SyncNodes(nodes, "http://10.0.0.1:8080")

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	str := string(content)

	if !strings.Contains(str, "# BEGIN FABRIC MESH") {
		t.Errorf("Expected begin block marker, got:\n%s", str)
	}
	if !strings.Contains(str, "10.0.0.1 alpha.fabric.mesh") {
		t.Errorf("Expected alpha node entry, got:\n%s", str)
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
		t.Errorf("Expected node entry to be removed, got:\n%s", cleanedStr)
	}
}

func TestHostsSanitizationRejection(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-hosts-sanitize-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("127.0.0.1 localhost\n")
	tmpFile.Close()

	mgr := NewSystemDNSManager("fabric.mesh")
	defer mgr.Teardown()
	mgr.hostsPath = tmpFile.Name()
	mgr.useResolved = false

	maliciousNodes := []protocol.NodeMetadata{
		{Hostname: "valid-node"},
		{Hostname: "poison\n10.0.0.99 evil.com"},
		{Hostname: "node with spaces"},
		{Hostname: "invalid_underscore"},
	}

	mgr.updateHostsBlock(maliciousNodes, "10.0.0.1")

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	str := string(content)

	if !strings.Contains(str, "10.0.0.1 valid-node.fabric.mesh") {
		t.Errorf("expected valid-node to be present in hosts file, got:\n%s", str)
	}
	if strings.Contains(str, "evil.com") {
		t.Errorf("expected injection attempt with evil.com to be rejected, got:\n%s", str)
	}
	if strings.Contains(str, "node with spaces") {
		t.Errorf("expected spaces to be rejected, got:\n%s", str)
	}
}

func TestConcurrentHostsUpdates(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-hosts-concurrent-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("127.0.0.1 localhost\n")
	tmpFile.Close()

	mgr := NewSystemDNSManager("fabric.mesh")
	defer mgr.Teardown()
	mgr.hostsPath = tmpFile.Name()
	mgr.useResolved = false

	done := make(chan struct{})
	for i := 0; i < 5; i++ {
		go func(id int) {
			nodes := []protocol.NodeMetadata{
				{Hostname: "node-1"},
				{Hostname: "node-2"},
			}
			for j := 0; j < 20; j++ {
				mgr.updateHostsBlock(nodes, "10.0.0.1")
				mgr.cleanHostsBlock()
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	// Verify file is readable and valid
	_, err = os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("hosts file corrupt or unreadable after concurrent writes: %v", err)
	}
}

func TestCentralizedCacheEviction(t *testing.T) {
	mgr := NewSystemDNSManager("fabric.mesh")
	defer mgr.Teardown()

	m := new(dns.Msg)
	m.SetQuestion("short-ttl.fabric.mesh.", dns.TypeA)
	respMsg := new(dns.Msg)
	respMsg.SetReply(m)
	rr, _ := dns.NewRR("short-ttl.fabric.mesh. 1 IN A 10.0.0.5")
	respMsg.Answer = append(respMsg.Answer, rr)
	wire, _ := respMsg.Pack()

	mgr.HandleDNSResponse(protocol.DNSResponse{
		Type:      protocol.TypeDNSResponse,
		SessionID: "sess-ttl",
		RCode:     dns.RcodeSuccess,
		TTL:       1, // 1 second TTL
		Data:      base64.StdEncoding.EncodeToString(wire),
	})

	mgr.cacheMux.RLock()
	_, found := mgr.cache["short-ttl.fabric.mesh."]
	mgr.cacheMux.RUnlock()
	if !found {
		t.Fatalf("expected entry to be cached initially")
	}

	// Wait for background ticker eviction (runs every 1s)
	time.Sleep(2200 * time.Millisecond)

	mgr.cacheMux.RLock()
	_, foundAfter := mgr.cache["short-ttl.fabric.mesh."]
	mgr.cacheMux.RUnlock()
	if foundAfter {
		t.Errorf("expected entry to be evicted by central ticker loop after TTL expiry")
	}
}

