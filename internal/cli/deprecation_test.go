package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWarnDeprecated(t *testing.T) {
	var buf bytes.Buffer
	SetDeprecationWriter(&buf)
	defer SetDeprecationWriter(nil)

	WarnDeprecated("fabric node ls", "fabric thread ls")

	got := buf.String()
	expected := "Warning: 'fabric node ls' is deprecated. Use 'fabric thread ls' instead.\n"
	if got != expected {
		t.Fatalf("expected deprecation message %q, got %q", expected, got)
	}
}

func TestStderrDeprecationDoesNotCorruptStdout(t *testing.T) {
	var stderrBuf bytes.Buffer
	var stdoutBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	// Simulate command writing JSON to stdout while emitting deprecation to stderr
	WarnDeprecated("fabric setup", "fabric init")
	stdoutBuf.WriteString(`{"status": "ok"}` + "\n")

	if !strings.Contains(stderrBuf.String(), "Warning: 'fabric setup' is deprecated. Use 'fabric init' instead.") {
		t.Errorf("expected deprecation warning in stderr, got %q", stderrBuf.String())
	}
	if stdoutBuf.String() != "{\"status\": \"ok\"}\n" {
		t.Errorf("expected clean stdout, got %q", stdoutBuf.String())
	}
}

func TestGetConfigDeprecationWarnings(t *testing.T) {
	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	// Reset flags
	serverFlag = ""
	hostFlag = "wss://legacy-host:8443/ws"
	remoteFlag = ""
	directFlag = "192.168.1.10:8443"
	defer func() {
		serverFlag = ""
		hostFlag = ""
		remoteFlag = ""
		directFlag = ""
	}()

	cfg := GetConfig()
	if cfg.Host != "wss://legacy-host:8443/ws" {
		t.Errorf("expected Host %q, got %q", "wss://legacy-host:8443/ws", cfg.Host)
	}
	if cfg.DirectAddress != "192.168.1.10:8443" {
		t.Errorf("expected DirectAddress %q, got %q", "192.168.1.10:8443", cfg.DirectAddress)
	}

	errOut := stderrBuf.String()
	if !strings.Contains(errOut, "Warning: '--host / -H' is deprecated. Use '--server / -s' instead.") {
		t.Errorf("expected --host deprecation warning, got %q", errOut)
	}
	if !strings.Contains(errOut, "Warning: '--direct' is deprecated. Use '--remote' instead.") {
		t.Errorf("expected --direct deprecation warning, got %q", errOut)
	}
}

func TestNormalizeServiceRole(t *testing.T) {
	tests := []struct {
		args     []string
		expected string
	}{
		{nil, "thread"},
		{[]string{}, "thread"},
		{[]string{"node"}, "thread"},
		{[]string{"agent"}, "thread"},
		{[]string{"NODE"}, "thread"},
		{[]string{"AGENT"}, "thread"},
		{[]string{"thread"}, "thread"},
		{[]string{"server"}, "server"},
		{[]string{"socket"}, "server"},
		{[]string{"hub"}, "server"},
		{[]string{"both"}, "both"},
	}
	for _, tc := range tests {
		got := normalizeServiceRole(tc.args)
		if got != tc.expected {
			t.Errorf("normalizeServiceRole(%v) = %q, want %q", tc.args, got, tc.expected)
		}
	}
}

