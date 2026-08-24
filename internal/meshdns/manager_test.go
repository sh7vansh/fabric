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
