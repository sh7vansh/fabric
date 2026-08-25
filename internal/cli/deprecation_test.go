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
