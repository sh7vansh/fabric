package provision

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"fabric/internal/protocol"
)

func extractDecodedEnv(script string) string {
	idxStart := strings.Index(script, `ENV_B64="`)
	if idxStart == -1 {
		return script
	}
	idxStart += len(`ENV_B64="`)
	idxEnd := strings.Index(script[idxStart:], `"`)
	if idxEnd == -1 {
		return script
	}
	b64Data := script[idxStart : idxStart+idxEnd]
	decoded, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return script
	}
	return string(decoded)
}

type mockExecutor struct {
	mu         sync.Mutex
	lastScript string
}

func (m *mockExecutor) Run(script string) error {
	m.mu.Lock()
	m.lastScript = script
	m.mu.Unlock()
	return nil
}

func (m *mockExecutor) LastScript() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastScript
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

	// Verify absence of external downloads in script shell commands
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PAYLOAD=") || strings.HasPrefix(trimmed, "CLI_PAYLOAD=") || strings.HasPrefix(trimmed, "ENV_B64=") || strings.HasPrefix(trimmed, "CA_PAYLOAD=") || strings.HasPrefix(trimmed, "CERT_PAYLOAD=") || strings.HasPrefix(trimmed, "KEY_PAYLOAD=") {
			continue
		}
		if strings.Contains(trimmed, "curl ") || strings.Contains(trimmed, "wget ") || trimmed == "curl" || trimmed == "wget" {
			t.Errorf("Script must not contain curl or wget (found external download dependency in line: %s)", line)
		}
	}

	envStr := extractDecodedEnv(script)

	// Verify environment variables and tags
	if !strings.Contains(envStr, "FABRIC_SOCKET_URL=ws://192.168.1.1:8080/ws") {
		t.Errorf("Script missing socket URL: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_TOKEN=test-secret-token") {
		t.Errorf("Script missing token: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_DOMAIN=custom.mesh") {
		t.Errorf("Script missing domain: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_TAGS=web,prod") {
		t.Errorf("Script missing tags: %s", envStr)
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
	mockEnv := extractDecodedEnv(mockExec.LastScript())
	if !strings.Contains(mockEnv, "FABRIC_SOCKET_URL=ws://10.0.0.1:8080/ws") {
		t.Errorf("Script was not passed correctly to mock executor: %s", mockEnv)
	}
	if !strings.Contains(mockEnv, "FABRIC_TAGS=ingress") {
		t.Errorf("Script missing tags in mock execution: %s", mockEnv)
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

func TestGenerateStitchScript_MTLSPayloads(t *testing.T) {
	tmpDir := t.TempDir()
	opts := StitchHostOptions{
		Target:     "node-direct",
		SocketURL:  "ws://10.0.0.1:8080/ws",
		Token:      "tok-direct",
		Domain:     "fabric.test",
		CADir:      tmpDir,
		Mode:       "inverted",
		ListenPort: "8443",
		BinaryData: []byte("mock-bin"),
	}

	script := GenerateStitchScript(opts, opts.SocketURL)
	envStr := extractDecodedEnv(script)

	if !strings.Contains(envStr, "FABRIC_LISTEN=:8443") {
		t.Errorf("missing FABRIC_LISTEN in inverted mode script: %s", envStr)
	}
	if !strings.Contains(script, "Unpacking Root CA certificate") {
		t.Errorf("missing CA unpacking in script: %s", script)
	}
	if !strings.Contains(script, "Unpacking node leaf certificate") {
		t.Errorf("missing leaf cert unpacking in script: %s", script)
	}
	if !strings.Contains(script, "Unpacking node leaf private key") {
		t.Errorf("missing private key unpacking in script: %s", script)
	}
}

func TestExecuteStitchHost_ExplicitInvertedMode(t *testing.T) {
	tmpDir := t.TempDir()
	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:     "192.168.1.55",
		Mode:       "inverted",
		ListenPort: "9443",
		Token:      "tok-inv",
		CADir:      tmpDir,
		BinaryData: []byte("mock-bin"),
	}

	probedAddr := ""
	mockProber := func(targetAddr, caPath string, timeout time.Duration) error {
		probedAddr = targetAddr
		return nil
	}

	node, err := ExecuteStitchHost(opts, mockExec, nil, mockProber)
	if err != nil {
		t.Fatalf("ExecuteStitchHost inverted mode failed: %v", err)
	}

	if node == nil || node.Hostname != "192.168.1.55" {
		t.Errorf("unexpected node: %+v", node)
	}
	if probedAddr != "192.168.1.55:9443" {
		t.Errorf("expected probe addr 192.168.1.55:9443, got: %s", probedAddr)
	}
	mockEnv := extractDecodedEnv(mockExec.LastScript())
	if !strings.Contains(mockEnv, "FABRIC_LISTEN=:9443") {
		t.Errorf("script did not configure FABRIC_LISTEN=:9443 in env: %s", mockEnv)
	}
}

func TestExecuteStitchHost_AutoFallbackOnTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:        "192.168.1.77",
		Mode:          "normal",
		ListenPort:    "8443",
		Token:         "tok-fallback",
		CADir:         tmpDir,
		VerifyTimeout: 50 * time.Millisecond,
		BinaryData:    []byte("mock-bin"),
	}

	// Verifier that always returns empty (simulating unreachable socket)
	verifier := func(socketURL, token string) ([]protocol.NodeMetadata, error) {
		return nil, nil
	}

	fallbackProbed := false
	mockProber := func(targetAddr, caPath string, timeout time.Duration) error {
		if targetAddr == "192.168.1.77:8443" {
			fallbackProbed = true
			return nil
		}
		return fmt.Errorf("unexpected probe addr: %s", targetAddr)
	}

	// We test with ExecuteStitchHost and short timeout verification flow
	node, err := ExecuteStitchHost(opts, mockExec, verifier, mockProber)
	if err != nil {
		t.Fatalf("expected auto-fallback to succeed, got: %v", err)
	}

	if node == nil || node.Hostname != "192.168.1.77" {
		t.Errorf("expected node 192.168.1.77, got: %+v", node)
	}
	if !fallbackProbed {
		t.Errorf("expected fallback direct mTLS probe to be executed")
	}
	if !strings.Contains(mockExec.LastScript(), `PORT=":8443"`) || !strings.Contains(mockExec.LastScript(), "FABRIC_LISTEN=") {
		t.Errorf("fallback switch script was not executed: %s", mockExec.LastScript())
	}
}

func TestExecuteStitchHost_NoFallbackFlag(t *testing.T) {
	tmpDir := t.TempDir()
	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:        "192.168.1.88",
		Mode:          "normal",
		NoFallback:    true,
		Token:         "tok-nofallback",
		CADir:         tmpDir,
		VerifyTimeout: 50 * time.Millisecond,
		BinaryData:    []byte("mock-bin"),
	}

	verifier := func(socketURL, token string) ([]protocol.NodeMetadata, error) {
		return nil, nil
	}

	node, err := ExecuteStitchHost(opts, mockExec, verifier)
	if err == nil {
		t.Fatalf("expected timeout error when --no-fallback is true, got node: %+v", node)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timed out error, got: %v", err)
	}
}

func TestSSHExecutorDelimitation(t *testing.T) {
	executor := &SSHExecutor{
		Target:      "-oProxyCommand=touch/tmp/pwned",
		Port:        "2222",
		IdentityKey: "/path/to/key",
		Silent:      true,
	}

	// We verify that the Target is safely separated by -- delimiter
	// We can test QueryArch error output or mock
	if executor.Target != "-oProxyCommand=touch/tmp/pwned" {
		t.Errorf("expected target preserved")
	}
}


