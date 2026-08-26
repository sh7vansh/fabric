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

	// Test stitch discover with CIDR deprecation warning
	stitchDiscoverCmd.RunE(stitchDiscoverCmd, []string{"127.0.0.1/32"})

	expectedMsg := "Warning: 'fabric stitch discover 127.0.0.1/32' is deprecated. Use 'fabric stitch 127.0.0.1/32' instead.\n"
	if !strings.Contains(stderrBuf.String(), expectedMsg) {
		t.Errorf("expected %q, got %q", expectedMsg, stderrBuf.String())
	}
}

func TestResolveStitchMode(t *testing.T) {
	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	// Valid modes
	tests := []struct {
		modeFlag string
		remote   bool
		inverted bool
		direct   bool
		expected string
		wantErr  bool
	}{
		{modeFlag: "local", expected: "local"},
		{modeFlag: "remote", expected: "remote"},
		{modeFlag: "normal", expected: "local"},
		{modeFlag: "inverted", expected: "remote"},
		{remote: true, expected: "remote"},
		{inverted: true, expected: "remote"},
		{direct: true, expected: "remote"},
		{modeFlag: "unknown", wantErr: true},
	}

	for _, tt := range tests {
		stderrBuf.Reset()
		mode, err := resolveStitchMode(tt.modeFlag, tt.remote, tt.inverted, tt.direct)
		if tt.wantErr {
			if err == nil {
				t.Errorf("resolveStitchMode(%q, %v, %v, %v) expected error, got nil", tt.modeFlag, tt.remote, tt.inverted, tt.direct)
			} else if !strings.Contains(err.Error(), "must be 'local' or 'remote'") {
				t.Errorf("resolveStitchMode error message %q should contain 'must be \\'local\\' or \\'remote\\''", err.Error())
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveStitchMode(%q, %v, %v, %v) unexpected error: %v", tt.modeFlag, tt.remote, tt.inverted, tt.direct, err)
		}
		if mode != tt.expected {
			t.Errorf("resolveStitchMode(%q, %v, %v, %v) = %q, want %q", tt.modeFlag, tt.remote, tt.inverted, tt.direct, mode, tt.expected)
		}
		if tt.inverted {
			if !strings.Contains(stderrBuf.String(), "Warning: '--inverted' is deprecated. Use '--mode=remote' or '--remote' instead.") {
				t.Errorf("expected '--inverted' deprecation warning, got %q", stderrBuf.String())
			}
		}
		if tt.direct {
			if !strings.Contains(stderrBuf.String(), "Warning: '--direct' is deprecated. Use '--mode=remote' or '--remote' instead.") {
				t.Errorf("expected '--direct' deprecation warning, got %q", stderrBuf.String())
			}
		}
	}
}
