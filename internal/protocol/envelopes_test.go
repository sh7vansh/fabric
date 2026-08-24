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
	}

	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Failed to marshal Handshake: %v", err)
	}

	var h2 Handshake
	if err := json.Unmarshal(b, &h2); err != nil {
		t.Fatalf("Failed to unmarshal Handshake: %v", err)
	}

	if h2.Hostname != h.Hostname || h2.Token != h.Token {
		t.Errorf("Unmarshaled struct does not match original: got %+v, want %+v", h2, h)
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
