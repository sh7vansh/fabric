package protocol

import (
	"testing"
)

func TestValidateProxyDestination(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		port      int
		wantAddr  string
		expectErr bool
	}{
		{"default localhost valid port", "", 8080, "127.0.0.1:8080", false},
		{"explicit localhost", "127.0.0.1", 3000, "127.0.0.1:3000", false},
		{"valid LAN IP", "192.168.1.50", 443, "192.168.1.50:443", false},
		{"invalid port 0", "127.0.0.1", 0, "", true},
		{"invalid negative port", "127.0.0.1", -1, "", true},
		{"invalid port > 65535", "127.0.0.1", 70000, "", true},
		{"blocked AWS/Azure metadata IP", "169.254.169.254", 80, "", true},
		{"blocked link-local IP", "169.254.1.1", 80, "", true},
		{"blocked cloud metadata hostname instance-data", "instance-data", 80, "", true},
		{"blocked GCP metadata hostname", "metadata.google.internal", 80, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := ValidateProxyDestination(tt.host, tt.port)
			if tt.expectErr && err == nil {
				t.Errorf("expected error for (%q, %d), got addr %q", tt.host, tt.port, addr)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error for (%q, %d): %v", tt.host, tt.port, err)
			}
			if !tt.expectErr && addr != tt.wantAddr {
				t.Errorf("got addr %q, want %q", addr, tt.wantAddr)
			}
		})
	}
}
