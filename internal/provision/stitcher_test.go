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

func (m *mockExecutor) QueryArch() (string, string, error) {
	return "linux", "amd64", nil
}

func TestPackageBinaryPayload(t *testing.T) {
	fakeData := []byte("#!/bin/sh\necho 'fake fabric-node binary'")
	payload, err := PackageBinaryPayload(fakeData)
	if err != nil {
		t.Fatalf("PackageBinaryPayload failed: %v", err)
	}
	if payload == "" {
		t.Fatalf("expected non-empty payload string")
	}

	emptyPayload, err := PackageBinaryPayload(nil)
	if err != nil || emptyPayload != "" {
		t.Errorf("expected empty payload for nil data, got: %s", emptyPayload)
	}
}

func TestGenerateStitchScript_ZeroInternetAndTags(t *testing.T) {
	fakeBinary := []byte("binary-executable-content")
	opts := StitchHostOptions{
		Target:     "192.168.1.100",
		Token:      "test-secret-token",
		Domain:     "custom.mesh",
		Tags:       []string{"web", "prod"},
		BinaryData: fakeBinary,
	}

	script := GenerateStitchScript(opts, "ws://192.168.1.1:8080/ws")

	// Verify absence of external downloads
	if strings.Contains(script, "curl") || strings.Contains(script, "wget") {
		t.Errorf("Script must not contain curl or wget (found external download dependency)")
	}

	// Verify environment variables and tags
	if !strings.Contains(script, "FABRIC_SOCKET_URL=ws://192.168.1.1:8080/ws") {
		t.Errorf("Script missing socket URL: %s", script)
	}
	if !strings.Contains(script, "FABRIC_TOKEN=test-secret-token") {
		t.Errorf("Script missing token: %s", script)
	}
	if !strings.Contains(script, "FABRIC_DOMAIN=custom.mesh") {
		t.Errorf("Script missing domain: %s", script)
	}
	if !strings.Contains(script, "FABRIC_TAGS=web,prod") {
		t.Errorf("Script missing tags: %s", script)
	}

	// Verify payload embedding and extraction
	if !strings.Contains(script, "Unpacking injected fabric-node binary") {
		t.Errorf("Script missing payload unpacking logic: %s", script)
	}
	if !strings.Contains(script, "Validated binary integrity") {
		t.Errorf("Script missing binary integrity check: %s", script)
	}
}

func TestGenerateStitchScript_MultiTierInit(t *testing.T) {
	opts := StitchHostOptions{
		Target:     "10.0.0.5",
		Token:      "cluster-token",
		Domain:     "fabric.mesh",
		Tags:       []string{"db"},
		BinaryData: []byte("mock-data"),
	}

	script := GenerateStitchScript(opts, "ws://10.0.0.1:8080/ws")

	// Tier 1: Root / system systemd
	if !strings.Contains(script, "/etc/systemd/system/fabric-node.service") {
		t.Errorf("Script missing Tier 1 systemd unit path")
	}

	// Tier 2: Non-root user systemd
	if !strings.Contains(script, ".config/systemd/user/fabric-node.service") {
		t.Errorf("Script missing Tier 2 user unit path")
	}
	if !strings.Contains(script, "loginctl enable-linger") {
		t.Errorf("Script missing loginctl enable-linger for non-root users")
	}
	if !strings.Contains(script, "systemctl --user") {
		t.Errorf("Script missing systemctl --user command for non-root")
	}

	// Tier 3: Standalone supervisor daemon & PID locking
	if !strings.Contains(script, "fabric-node-supervisor.sh") {
		t.Errorf("Script missing Tier 3 standalone supervisor script")
	}
	if !strings.Contains(script, "fabric-node.pid") {
		t.Errorf("Script missing PID file management")
	}
}

func TestExecuteStitchHostWithMock(t *testing.T) {
	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:     "node-1",
		SocketURL:  "ws://10.0.0.1:8080/ws",
		Token:      "tok",
		Domain:     "fabric.mesh",
		Tags:       []string{"ingress"},
		BinaryData: []byte("mock-binary"),
	}

	verifier := func(socketURL, token string) ([]protocol.NodeMetadata, error) {
		return []protocol.NodeMetadata{
			{Hostname: "node-1", Status: "online", Tags: []string{"ingress"}},
		}, nil
	}

	node, err := ExecuteStitchHost(opts, mockExec, verifier)
	if err != nil {
		t.Fatalf("ExecuteStitchHost failed: %v", err)
	}

	if node == nil || node.Hostname != "node-1" {
		t.Errorf("Expected node-1 metadata, got: %+v", node)
	}
	if len(node.Tags) != 1 || node.Tags[0] != "ingress" {
		t.Errorf("Expected tag ingress, got: %v", node.Tags)
	}
	if !strings.Contains(mockExec.lastScript, "FABRIC_SOCKET_URL=ws://10.0.0.1:8080/ws") {
		t.Errorf("Script was not passed correctly to mock executor")
	}
	if !strings.Contains(mockExec.lastScript, "FABRIC_TAGS=ingress") {
		t.Errorf("Script missing tags in mock execution")
	}
}

func TestProvisionerBatch(t *testing.T) {
	mockExec := &mockExecutor{}
	verifier := func(socketURL, token string) ([]protocol.NodeMetadata, error) {
		return []protocol.NodeMetadata{
			{Hostname: "host-a", Status: "online"},
			{Hostname: "host-b", Status: "online"},
		}, nil
	}

	provisioner := NewProvisioner(mockExec, verifier)

	targets := []StitchHostOptions{
		{Target: "host-a", SocketURL: "ws://10.0.0.1:8080/ws", Token: "tok", BinaryData: []byte("bin")},
		{Target: "host-b", SocketURL: "ws://10.0.0.1:8080/ws", Token: "tok", BinaryData: []byte("bin")},
	}

	results, err := provisioner.ProvisionBatch(targets)
	if err != nil {
		t.Fatalf("ProvisionBatch failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, r := range results {
		if !r.Success {
			t.Errorf("expected target %s to succeed, got error: %v", r.Target, r.Error)
		}
	}
}
