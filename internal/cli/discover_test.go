package cli

import (
	"testing"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantCount   int
		firstIP     string
		lastIP      string
		expectError bool
	}{
		{
			name:        "Standard /30 subnet (4 IPs, 2 usable hosts)",
			input:       "192.168.1.0/30",
			wantCount:   2,
			firstIP:     "192.168.1.1",
			lastIP:      "192.168.1.2",
			expectError: false,
		},
		{
			name:        "Standard /24 subnet (256 IPs, 254 usable hosts)",
			input:       "10.0.5.0/24",
			wantCount:   254,
			firstIP:     "10.0.5.1",
			lastIP:      "10.0.5.254",
			expectError: false,
		},
		{
			name:        "Single IP address",
			input:       "192.168.1.50",
			wantCount:   1,
			firstIP:     "192.168.1.50",
			lastIP:      "192.168.1.50",
			expectError: false,
		},
		{
			name:        "Comma-separated list with mixed single IP and /30",
			input:       "10.0.1.1, 10.0.1.2, 192.168.1.0/30",
			wantCount:   4,
			firstIP:     "10.0.1.1",
			lastIP:      "192.168.1.2",
			expectError: false,
		},
		{
			name:        "/32 single host subnet",
			input:       "192.168.1.100/32",
			wantCount:   1,
			firstIP:     "192.168.1.100",
			lastIP:      "192.168.1.100",
			expectError: false,
		},
		{
			name:        "Invalid CIDR notation",
			input:       "999.999.999.999/24",
			expectError: true,
		},
		{
			name:        "Subnet exceeding safety limit (/8)",
			input:       "10.0.0.0/8",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := ParseTargets(tt.input)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseTargets(%q) error = %v, expectError = %v", tt.input, err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			if len(targets) != tt.wantCount {
				t.Errorf("ParseTargets(%q) count = %d; want %d", tt.input, len(targets), tt.wantCount)
			}
			if len(targets) > 0 {
				if targets[0] != tt.firstIP {
					t.Errorf("First target = %q; want %q", targets[0], tt.firstIP)
				}
				if targets[len(targets)-1] != tt.lastIP {
					t.Errorf("Last target = %q; want %q", targets[len(targets)-1], tt.lastIP)
				}
			}
		})
	}
}

func TestGetDefaultLocalCIDR(t *testing.T) {
	cidr, err := GetDefaultLocalCIDR()
	if err != nil {
		t.Logf("GetDefaultLocalCIDR returned error (expected in restricted test environments): %v", err)
		return
	}
	t.Logf("Detected local CIDR: %s", cidr)
	if cidr == "" {
		t.Errorf("Expected non-empty CIDR")
	}
}
