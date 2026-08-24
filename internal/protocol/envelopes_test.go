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
