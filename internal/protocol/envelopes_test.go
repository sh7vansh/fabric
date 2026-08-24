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
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Failed to marshal NodeMetadata: %v", err)
	}

	var m2 NodeMetadata
	if err := json.Unmarshal(b, &m2); err != nil {
		t.Fatalf("Failed to unmarshal NodeMetadata: %v", err)
	}

	if m2.Hostname != m.Hostname || len(m2.Tags) != 2 || m2.Tags[0] != "gpu" || m2.Tags[1] != "worker" {
		t.Errorf("Unmarshaled struct does not match original: got %+v, want %+v", m2, m)
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
