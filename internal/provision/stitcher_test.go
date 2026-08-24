package provision

import (
	"strings"
	"testing"

	"fabric/internal/protocol"
)

type mockExecutor struct {
	lastScript string
}

func (m *mockExecutor) Run(script string) error {
	m.lastScript = script
	return nil
}

func TestGenerateStitchScript(t *testing.T) {
	opts := StitchHostOptions{
		Target: "192.168.1.100",
		Token:  "test-secret-token",
		Domain: "custom.mesh",
	}

	script := GenerateStitchScript(opts, "ws://192.168.1.1:8080/ws")

	if !strings.Contains(script, "FABRIC_SOCKET_URL=ws://192.168.1.1:8080/ws") {
		t.Errorf("Script missing socket URL: %s", script)
	}
	if !strings.Contains(script, "FABRIC_TOKEN=test-secret-token") {
		t.Errorf("Script missing token: %s", script)
	}
	if !strings.Contains(script, "FABRIC_DOMAIN=custom.mesh") {
		t.Errorf("Script missing domain: %s", script)
	}
}

func TestExecuteStitchHostWithMock(t *testing.T) {
	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:    "node-1",
		SocketURL: "ws://10.0.0.1:8080/ws",
		Token:     "tok",
		Domain:    "fabric.mesh",
	}

	verifier := func(socketURL, token string) ([]protocol.NodeMetadata, error) {
		return []protocol.NodeMetadata{
			{Hostname: "node-1", Status: "online"},
		}, nil
	}

	node, err := ExecuteStitchHost(opts, mockExec, verifier)
	if err != nil {
		t.Fatalf("ExecuteStitchHost failed: %v", err)
	}

	if node == nil || node.Hostname != "node-1" {
		t.Errorf("Expected node-1 metadata, got: %+v", node)
	}
	if !strings.Contains(mockExec.lastScript, "FABRIC_SOCKET_URL=ws://10.0.0.1:8080/ws") {
		t.Errorf("Script was not passed correctly to mock executor")
	}
}
