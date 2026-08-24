package main

import (
	"encoding/base64"
	"testing"

	"fabric/internal/protocol"

	"github.com/miekg/dns"
)

func TestProcessDNSQuery(t *testing.T) {
	nodesLock.Lock()
	nodes = make(map[string]*NodeState)
	nodes["node-1"] = &NodeState{
		Metadata: protocol.NodeMetadata{
			Hostname: "node-1",
			Status:   "online",
		},
	}
	nodesLock.Unlock()

	domain := "fabric.mesh"
	proxyIP := "10.0.0.1"

	// 1. Online Node
	m := new(dns.Msg)
	m.SetQuestion("node-1.fabric.mesh.", dns.TypeA)
	wire, _ := m.Pack()

	q := protocol.DNSQuery{
		Type:      protocol.TypeDNSQuery,
		SessionID: "sess-1",
		Data:      base64.StdEncoding.EncodeToString(wire),
	}

	resp := ProcessDNSQuery(q, domain, proxyIP)

	if resp.RCode != dns.RcodeSuccess {
		t.Errorf("Expected RCodeSuccess, got %d", resp.RCode)
	}

	respWire, _ := base64.StdEncoding.DecodeString(resp.Data)
	mResp := new(dns.Msg)
	mResp.Unpack(respWire)

	if len(mResp.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(mResp.Answer))
	}

	aRecord, ok := mResp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Expected A record")
	}

	if aRecord.A.String() != proxyIP {
		t.Errorf("Expected IP %s, got %s", proxyIP, aRecord.A.String())
	}
	if resp.TTL != 10 {
		t.Errorf("Expected TTL 10, got %d", resp.TTL)
	}

	// 2. Offline / Unknown Node
	m2 := new(dns.Msg)
	m2.SetQuestion("node-2.fabric.mesh.", dns.TypeA)
	wire2, _ := m2.Pack()

	q2 := protocol.DNSQuery{
		Type:      protocol.TypeDNSQuery,
		SessionID: "sess-2",
		Data:      base64.StdEncoding.EncodeToString(wire2),
	}

	resp2 := ProcessDNSQuery(q2, domain, proxyIP)

	if resp2.RCode != dns.RcodeNameError {
		t.Errorf("Expected RcodeNameError (NXDOMAIN), got %d", resp2.RCode)
	}
	if resp2.TTL != 5 {
		t.Errorf("Expected TTL 5, got %d", resp2.TTL)
	}
}
