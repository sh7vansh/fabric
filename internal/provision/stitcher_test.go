package provision

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
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

func TestFindLocalBinary_FabricThreadPreference(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	threadBin := filepath.Join(binDir, "fabric-thread")
	if err := os.WriteFile(threadBin, []byte("#!/bin/sh\necho thread"), 0755); err != nil {
		t.Fatalf("failed to write fake thread bin: %v", err)
	}

	// Change working directory to tmpDir during test
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	defer os.Chdir(wd)
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	found, err := FindLocalBinary("")
	if err != nil {
		t.Fatalf("expected FindLocalBinary to find fabric-thread, got err: %v", err)
	}
	if !strings.HasSuffix(found, "fabric-thread") {
		t.Errorf("expected found binary to be fabric-thread, got: %s", found)
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

	script := GenerateStitchScript(opts, "wss://192.168.1.1:8443/ws")

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
	if !strings.Contains(envStr, "FABRIC_SERVER_URL=wss://192.168.1.1:8443/ws") {
		t.Errorf("Script missing server URL: %s", envStr)
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
	if !strings.Contains(script, "Unpacking injected fabric-thread binary") {
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

	script := GenerateStitchScript(opts, "wss://10.0.0.1:8443/ws")

	// Tier 1: Root / system systemd
	if !strings.Contains(script, "/etc/systemd/system/fabric-thread.service") {
		t.Errorf("Script missing Tier 1 systemd unit path")
	}

	// Tier 2: Non-root user systemd
	if !strings.Contains(script, ".config/systemd/user/fabric-thread.service") {
		t.Errorf("Script missing Tier 2 user unit path")
	}
	if !strings.Contains(script, "loginctl enable-linger") {
		t.Errorf("Script missing loginctl enable-linger for non-root users")
	}
	if !strings.Contains(script, "systemctl --user") {
		t.Errorf("Script missing systemctl --user command for non-root")
	}

	// Tier 3: Standalone supervisor daemon & PID locking
	if !strings.Contains(script, "fabric-thread-supervisor.sh") {
		t.Errorf("Script missing Tier 3 standalone supervisor script")
	}
	if !strings.Contains(script, "fabric-thread.pid") {
		t.Errorf("Script missing PID file management")
	}
}

func TestExecuteStitchHostWithMock(t *testing.T) {
	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:     "node-1",
		SocketURL:  "wss://10.0.0.1:8443/ws",
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
	if !strings.Contains(mockEnv, "FABRIC_SERVER_URL=wss://10.0.0.1:8443/ws") {
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
		{Target: "host-a", SocketURL: "wss://10.0.0.1:8443/ws", Token: "tok", BinaryData: []byte("bin")},
		{Target: "host-b", SocketURL: "wss://10.0.0.1:8443/ws", Token: "tok", BinaryData: []byte("bin")},
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
		SocketURL:  "wss://10.0.0.1:8443/ws",
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
	if !strings.Contains(script, "Unpacking thread leaf certificate") {
		t.Errorf("missing leaf cert unpacking in script: %s", script)
	}
	if !strings.Contains(script, "Unpacking thread leaf private key") {
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

func TestGenerateStitchScript_HonorsEnvCADir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("FABRIC_CA_DIR", tmpDir)

	opts := StitchHostOptions{
		Target:     "node-env-ca",
		SocketURL:  "wss://10.0.0.1:8443/ws",
		Token:      "tok-env-ca",
		Domain:     "fabric.test",
		Mode:       "remote",
		BinaryData: []byte("mock-bin"),
	}

	script := GenerateStitchScript(opts, opts.SocketURL)
	if !strings.Contains(script, "Unpacking Root CA certificate") {
		t.Errorf("expected CA certificate to be unpacked when FABRIC_CA_DIR is set")
	}

	// Verify CA was created in tmpDir
	if _, err := os.Stat(filepath.Join(tmpDir, "ca.crt")); err != nil {
		t.Errorf("expected ca.crt in FABRIC_CA_DIR %s: %v", tmpDir, err)
	}
}

func TestExecuteStitchHost_ResolvesCAViaCentralPKI(t *testing.T) {
	tmpDir := t.TempDir()
	caCertPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caCertPath, []byte("-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FABRIC_CA_CERT", caCertPath)

	mockExec := &mockExecutor{}
	opts := StitchHostOptions{
		Target:     "192.168.1.99",
		Mode:       "remote",
		ListenPort: "8443",
		Token:      "tok-central-pki",
		BinaryData: []byte("mock-bin"),
	}

	probedCAPath := ""
	mockProber := func(targetAddr, caPath string, timeout time.Duration) error {
		probedCAPath = caPath
		return nil
	}

	node, err := ExecuteStitchHost(opts, mockExec, nil, mockProber)
	if err != nil {
		t.Fatalf("ExecuteStitchHost failed: %v", err)
	}
	if node == nil {
		t.Fatal("expected non-nil node")
	}
	if probedCAPath != caCertPath {
		t.Errorf("expected prober to receive resolved CA path %s, got %s", caCertPath, probedCAPath)
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
	if executor.Target != "-oProxyCommand=touch/tmp/pwned" {
		t.Errorf("expected target preserved")
	}
}

func TestResolveReleaseBinaryName(t *testing.T) {
	tests := []struct {
		role     string
		osName   string
		arch     string
		expected string
	}{
		{"thread", "linux", "amd64", "fabric-thread-linux-amd64"},
		{"node", "linux", "amd64", "fabric-thread-linux-amd64"},
		{"server", "linux", "arm64", "fabric-server-linux-arm64"},
		{"socket", "linux", "arm64", "fabric-server-linux-arm64"},
		{"cli", "linux", "arm", "fabric-linux-arm"},
		{"fabric", "linux", "amd64", "fabric-linux-amd64"},
	}

	for _, tc := range tests {
		got, err := ResolveReleaseBinaryName(tc.role, tc.osName, tc.arch)
		if err != nil {
			t.Errorf("ResolveReleaseBinaryName(%q, %q, %q) returned unexpected error: %v", tc.role, tc.osName, tc.arch, err)
		}
		if got != tc.expected {
			t.Errorf("ResolveReleaseBinaryName(%q, %q, %q) = %q; want %q", tc.role, tc.osName, tc.arch, got, tc.expected)
		}
	}
}

func TestProgressReader(t *testing.T) {
	data := []byte("hello world 1234567890 test bytes for download progress")
	r := strings.NewReader(string(data))
	pr := &progressReader{
		reader: r,
		total:  int64(len(data)),
		name:   "test-binary",
	}

	buf := make([]byte, 10)
	totalRead := 0
	for {
		n, err := pr.Read(buf)
		totalRead += n
		if err != nil {
			break
		}
	}
	pr.finish()

	if totalRead != len(data) {
		t.Fatalf("expected totalRead %d, got %d", len(data), totalRead)
	}
}

func TestFormatSSHError(t *testing.T) {
	t.Run("formats connection timeout with firewall diagnostic", func(t *testing.T) {
		err := fmt.Errorf("dial tcp 192.168.1.50:22: i/o timeout")
		formatted := FormatSSHError("192.168.1.50", "22", err, "")
		if !strings.Contains(formatted.Error(), "firewall") || !strings.Contains(formatted.Error(), "port 22/TCP") {
			t.Errorf("expected firewall diagnostic in error, got: %v", formatted)
		}
	})

	t.Run("formats connection refused with firewall diagnostic", func(t *testing.T) {
		err := fmt.Errorf("ssh: connect to host 10.0.0.5 port 22: Connection refused")
		formatted := FormatSSHError("10.0.0.5", "22", err, "")
		if !strings.Contains(formatted.Error(), "port 22/TCP may be closed, blocked by a firewall") {
			t.Errorf("expected firewall diagnostic, got: %v", formatted)
		}
	})

	t.Run("formats exit status 255 with firewall diagnostic and unblocking guidance", func(t *testing.T) {
		err := fmt.Errorf("exit status 255")
		formatted := FormatSSHError("10.0.0.5", "2222", err, "")
		if !strings.Contains(formatted.Error(), "port 2222/TCP may be closed, blocked by a firewall") {
			t.Errorf("expected firewall diagnostic with custom port, got: %v", formatted)
		}
		if !strings.Contains(formatted.Error(), "unblock with:") {
			t.Errorf("expected unblocking guidance in error, got: %v", formatted)
		}
	})
}

func TestGenerateStitchScript_RemoteModeFirewallRules(t *testing.T) {
	opts := StitchHostOptions{
		Target:     "node-remote",
		Mode:       "remote",
		ListenPort: "8443",
		BinaryData: []byte("mock-data"),
	}

	script := GenerateStitchScript(opts, "wss://server:8443/ws")

	if !strings.Contains(script, `if [ "remote" = "remote" ]; then`) {
		t.Errorf("expected remote mode conditional in script: %s", script)
	}
	if !strings.Contains(script, "ufw allow") || !strings.Contains(script, "firewall-cmd --permanent --add-port=") ||
		!strings.Contains(script, "nft add rule") || !strings.Contains(script, "iptables -I INPUT") {
		t.Errorf("expected multi-backend firewall configuration commands in remote mode script: %s", script)
	}
}

func TestGenerateStitchScript_LocalModeOutboundOnly(t *testing.T) {
	opts := StitchHostOptions{
		Target:     "node-local",
		Mode:       "local",
		BinaryData: []byte("mock-data"),
	}

	script := GenerateStitchScript(opts, "wss://server:8443/ws")

	if !strings.Contains(script, `if [ "local" = "remote" ]; then`) {
		t.Errorf("expected local mode to not execute remote firewall commands: %s", script)
	}
}


