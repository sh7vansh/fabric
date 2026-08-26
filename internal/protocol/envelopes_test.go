package protocol

import (
	"encoding/json"
	"testing"
)

func TestHandshakeJSON(t *testing.T) {
	h := Handshake{
		Type:     TypeHandshake,
		Hostname: "test-node",
		Token:    "secret123",
		Tags:     []string{"web", "prod"},
	}

	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Failed to marshal Handshake: %v", err)
	}

	var h2 Handshake
	if err := json.Unmarshal(b, &h2); err != nil {
		t.Fatalf("Failed to unmarshal Handshake: %v", err)
	}

	if h2.Hostname != h.Hostname || h2.Token != h.Token || len(h2.Tags) != 2 || h2.Tags[0] != "web" || h2.Tags[1] != "prod" {
		t.Errorf("Unmarshaled struct does not match original: got %+v, want %+v", h2, h)
	}
}

func TestNodeMetadataJSON(t *testing.T) {
	m := NodeMetadata{
		ID:          "test-node",
		Hostname:    "test-node",
		Domain:      "fabric.mesh",
		OS:          "linux",
		Arch:        "amd64",
		Version:     "1.0.0",
		Status:      "online",
		ConnectedAt: "2026-01-01T00:00:00Z",
		Tags:        []string{"gpu", "worker"},
		ServerID:    "srv-alpha",
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Failed to marshal NodeMetadata: %v", err)
	}

	var m2 ThreadMetadata
	if err := json.Unmarshal(b, &m2); err != nil {
		t.Fatalf("Failed to unmarshal ThreadMetadata: %v", err)
	}

	if m2.Hostname != m.Hostname || len(m2.Tags) != 2 || m2.Tags[0] != "gpu" || m2.Tags[1] != "worker" {
		t.Errorf("Unmarshaled struct does not match original: got %+v, want %+v", m2, m)
	}
	if m2.ServerID != "srv-alpha" || m2.GatewayID != "srv-alpha" {
		t.Errorf("Expected ServerID and GatewayID to be srv-alpha, got server_id=%q gateway_id=%q", m2.ServerID, m2.GatewayID)
	}

	// Test backward compatibility fallback with gateway_id only JSON
	legacyJSON := []byte(`{"id":"node-1","hostname":"node-1","gateway_id":"legacy-gw"}`)
	var mLegacy NodeMetadata
	if err := json.Unmarshal(legacyJSON, &mLegacy); err != nil {
		t.Fatalf("Failed to unmarshal legacy NodeMetadata JSON: %v", err)
	}
	if mLegacy.ServerID != "legacy-gw" || mLegacy.GatewayID != "legacy-gw" {
		t.Errorf("Expected legacy gateway_id to populate ServerID, got ServerID=%q GatewayID=%q", mLegacy.ServerID, mLegacy.GatewayID)
	}
}

func TestDNSQueryJSON(t *testing.T) {
	q := DNSQuery{
		Type:      TypeDNSQuery,
		SessionID: "session123",
		Name:      "test.fabric.mesh.",
		QType:     1,
		Data:      "base64data==",
	}

	b, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("Failed to marshal DNSQuery: %v", err)
	}

	var q2 DNSQuery
	if err := json.Unmarshal(b, &q2); err != nil {
		t.Fatalf("Failed to unmarshal DNSQuery: %v", err)
	}

	if q2.SessionID != q.SessionID || q2.Name != q.Name || q2.QType != q.QType || q2.Data != q.Data {
		t.Errorf("Unmarshaled struct does not match original: got %+v, want %+v", q2, q)
	}
}

func TestDNSResponseJSON(t *testing.T) {
	resp := DNSResponse{
		Type:      TypeDNSResponse,
		SessionID: "session123",
		RCode:     0,
		TTL:       10,
		Data:      "base64data==",
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal DNSResponse: %v", err)
	}

	var resp2 DNSResponse
	if err := json.Unmarshal(b, &resp2); err != nil {
		t.Fatalf("Failed to unmarshal DNSResponse: %v", err)
	}

	if resp2.SessionID != resp.SessionID || resp2.RCode != resp.RCode || resp2.TTL != resp.TTL || resp2.Data != resp.Data {
		t.Errorf("Unmarshaled struct does not match original: got %+v, want %+v", resp2, resp)
	}
}

func TestFederationEnvelopesJSON(t *testing.T) {
	hello := GatewayHello{
		Type:         TypeGatewayHello,
		GatewayID:    "gw-us-east",
		Domain:       "us-east.fabric",
		Region:       "us-east-1",
		Capabilities: []string{"exec", "cp", "proxy", "dns"},
		IsLeaf:       false,
	}
	b, err := json.Marshal(hello)
	if err != nil {
		t.Fatalf("Marshal GatewayHello failed: %v", err)
	}
	var hello2 GatewayHello
	if err := json.Unmarshal(b, &hello2); err != nil {
		t.Fatalf("Unmarshal GatewayHello failed: %v", err)
	}
	if hello2.GatewayID != "gw-us-east" || hello2.ServerID != "gw-us-east" || hello2.Region != "us-east-1" || len(hello2.Capabilities) != 4 {
		t.Errorf("Mismatch in GatewayHello: %+v", hello2)
	}

	// Test ServerHello canonical marshal / unmarshal
	srvHello := ServerHello{
		Type:         TypeServerHello,
		ServerID:     "srv-us-east",
		Domain:       "us-east.fabric",
		Region:       "us-east-1",
		Capabilities: []string{"exec", "cp", "proxy", "dns"},
		IsLeaf:       true,
	}
	bSrv, err := json.Marshal(srvHello)
	if err != nil {
		t.Fatalf("Marshal ServerHello failed: %v", err)
	}
	var srvHello2 ServerHello
	if err := json.Unmarshal(bSrv, &srvHello2); err != nil {
		t.Fatalf("Unmarshal ServerHello failed: %v", err)
	}
	if srvHello2.ServerID != "srv-us-east" || srvHello2.GatewayID != "srv-us-east" || srvHello2.Type != TypeServerHello {
		t.Errorf("Mismatch in ServerHello: %+v", srvHello2)
	}

	// Test ServerHeartbeat / GatewayHeartbeat
	hb := ServerHeartbeat{
		Type:      TypeServerHeartbeat,
		ServerID:  "srv-1",
		Timestamp: "2026-08-26T00:00:00Z",
	}
	bHb, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("Marshal ServerHeartbeat failed: %v", err)
	}
	var hb2 GatewayHeartbeat
	if err := json.Unmarshal(bHb, &hb2); err != nil {
		t.Fatalf("Unmarshal ServerHeartbeat failed: %v", err)
	}
	if hb2.ServerID != "srv-1" || hb2.GatewayID != "srv-1" {
		t.Errorf("Mismatch in ServerHeartbeat: %+v", hb2)
	}

	// Test ServerPeerInfo
	peerInfo := ServerPeerInfo{
		ServerID:    "srv-1",
		Domain:      "srv-1.fabric",
		Region:      "eu-central-1",
		Topology:    "core",
		ThreadCount: 3,
		Status:      "connected",
	}
	bPeer, err := json.Marshal(peerInfo)
	if err != nil {
		t.Fatalf("Marshal ServerPeerInfo failed: %v", err)
	}
	var peerInfo2 GatewayPeerInfo
	if err := json.Unmarshal(bPeer, &peerInfo2); err != nil {
		t.Fatalf("Unmarshal ServerPeerInfo failed: %v", err)
	}
	if peerInfo2.ServerID != "srv-1" || peerInfo2.GatewayID != "srv-1" || peerInfo2.Topology != "core" {
		t.Errorf("Mismatch in ServerPeerInfo: %+v", peerInfo2)
	}

	adv := ThreadAdvertise{
		Type:      TypeThreadAdvertise,
		ServerID:  "gw-us-east",
		Nodes: []NodeMetadata{
			{
				ID:        "worker-1",
				Hostname:  "worker-1",
				ServerID:  "gw-us-east",
			},
		},
	}
	bAdv, err := json.Marshal(adv)
	if err != nil {
		t.Fatalf("Marshal ThreadAdvertise failed: %v", err)
	}
	var adv2 ThreadAdvertise
	if err := json.Unmarshal(bAdv, &adv2); err != nil {
		t.Fatalf("Unmarshal ThreadAdvertise failed: %v", err)
	}
	if adv2.GatewayID != "gw-us-east" || adv2.ServerID != "gw-us-east" || len(adv2.Nodes) != 1 || adv2.Nodes[0].ServerID != "gw-us-east" {
		t.Errorf("Mismatch in ThreadAdvertise: %+v", adv2)
	}

	with := ThreadWithdraw{
		Type:      TypeThreadWithdraw,
		ServerID:  "gw-us-east",
		Hostname:  "worker-1",
	}
	bWith, err := json.Marshal(with)
	if err != nil {
		t.Fatalf("Marshal ThreadWithdraw failed: %v", err)
	}
	var with2 ThreadWithdraw
	if err := json.Unmarshal(bWith, &with2); err != nil {
		t.Fatalf("Unmarshal ThreadWithdraw failed: %v", err)
	}
	if with2.GatewayID != "gw-us-east" || with2.ServerID != "gw-us-east" || with2.Hostname != "worker-1" {
		t.Errorf("Mismatch in ThreadWithdraw: %+v", with2)
	}
}
