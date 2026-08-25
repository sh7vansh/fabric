package cli

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestIsCIDR(t *testing.T) {
	tests := []struct {
		input  string
		isCIDR bool
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", true},
		{"172.16.0.0/16", true},
		{"192.168.1.50", false},
		{"user@192.168.1.50", false},
		{"user@192.168.1.50:22", false},
		{"hostname", false},
	}

	for _, tt := range tests {
		_, _, err := net.ParseCIDR(tt.input)
		got := (err == nil)
		if got != tt.isCIDR {
			t.Errorf("isCIDR(%q) = %v, want %v", tt.input, got, tt.isCIDR)
		}
	}
}

func TestStitchDeprecationWarning(t *testing.T) {
	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	// Test stitch discover deprecation warning
	stitchDiscoverCmd.RunE(stitchDiscoverCmd, []string{"127.0.0.1/32"})

	if !strings.Contains(stderrBuf.String(), "Warning: 'fabric stitch discover' is deprecated. Use 'fabric stitch' instead.") {
		t.Errorf("expected stitch discover deprecation warning, got %q", stderrBuf.String())
	}
}
