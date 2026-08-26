package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"fabric/internal/meshdns"
	"fabric/internal/protocol"
)

func TestAgentHandleExecStdout(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	req := protocol.ExecRequest{
		Command: "echo 'hello fabric agent'",
	}
	env, _ := json.Marshal(req)

	go ag.HandleExec(serverConn, env)

	var stdoutCaptured []byte
	var exitReceived bool

	for {
		frame, err := protocol.ReadFrame(clientConn)
		if err != nil {
			break
		}
		if frame.Type == protocol.StreamStdout {
			stdoutCaptured = append(stdoutCaptured, frame.Payload...)
		}
		if frame.Type == protocol.StreamExit {
			exitReceived = true
			if string(frame.Payload) != "0" {
				t.Errorf("expected exit code 0, got %s", string(frame.Payload))
			}
		}
	}

	if !exitReceived {
		t.Errorf("expected exit frame to be received")
	}
	if string(stdoutCaptured) != "hello fabric agent\n" {
		t.Errorf("expected 'hello fabric agent\\n', got %q", string(stdoutCaptured))
	}
}

func TestAgentHandleCopyDownloadAndUpload(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	tmpDir, err := os.MkdirTemp("", "fabric-agent-copy-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "sample.txt")
	_ = os.WriteFile(testFile, []byte("mesh file contents"), 0644)

	// 1. Test Download from Agent
	sConn1, cConn1 := net.Pipe()

	reqDownload := protocol.CopyRequest{
		Direction:  "download",
		RemotePath: testFile,
	}
	envDownload, _ := json.Marshal(reqDownload)

	go ag.HandleCopy(sConn1, envDownload)

	extractDir, _ := os.MkdirTemp("", "fabric-agent-extract-*")
	defer os.RemoveAll(extractDir)

	err = protocol.ExtractTar(cConn1, extractDir)
	if err != nil {
		t.Fatalf("ExtractTar failed: %v", err)
	}
	cConn1.Close()

	extractedContent, err := os.ReadFile(filepath.Join(extractDir, "sample.txt"))
	if err != nil || string(extractedContent) != "mesh file contents" {
		t.Errorf("extracted content mismatch: %v, %s", err, string(extractedContent))
	}
}

func TestAgentHandleProxy(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	// Start local TCP echo listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)

	sConn, cConn := net.Pipe()
	defer sConn.Close()
	defer cConn.Close()

	req := protocol.ProxyRequest{
		TargetHost: "127.0.0.1",
		TargetPort: tcpAddr.Port,
	}
	env, _ := json.Marshal(req)

	go ag.HandleProxy(sConn, env)

	// Send data through proxy client connection
	if _, err := cConn.Write([]byte("ping proxy")); err != nil {
		t.Fatalf("Write to proxy failed: %v", err)
	}

	buf := make([]byte, 32)
	n, err := cConn.Read(buf)
	if err != nil || string(buf[:n]) != "ping proxy" {
		t.Errorf("expected echo 'ping proxy', got %q, err: %v", string(buf[:n]), err)
	}
}

// TestAgentHandleProxy_Regression_NoInjectedBytes verifies that HandleProxy never writes
// any control or response envelope (such as ProxyResponse JSON) before or during proxying.
func TestAgentHandleProxy_Regression_NoInjectedBytes(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer targetLn.Close()

	targetReceived := make(chan []byte, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		targetReceived <- buf[:n]
		conn.Write([]byte("TARGET_RAW_RESPONSE"))
	}()

	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	sConn, cConn := net.Pipe()
	defer sConn.Close()
	defer cConn.Close()

	req := protocol.ProxyRequest{
		TargetHost: "127.0.0.1",
		TargetPort: targetPort,
	}
	env, _ := json.Marshal(req)

	go ag.HandleProxy(sConn, env)

	// Invariant: Before the client sends anything, the agent MUST NOT write any bytes (no ProxyResponse JSON).
	// Set a short read deadline on cConn.
	_ = cConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	n, readErr := cConn.Read(buf)
	if n > 0 {
		t.Fatalf("Regression violation: HandleProxy injected %d bytes before data phase: %q", n, string(buf[:n]))
	}
	if readErr == nil {
		t.Fatalf("expected read timeout or EOF, got nil error with 0 bytes")
	}

	// Reset deadline
	_ = cConn.SetReadDeadline(time.Time{})

	// Now send client raw payload
	clientPayload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'H', 'E', 'L', 'L', 'O'} // Simulated TLS-like bytes
	if _, err := cConn.Write(clientPayload); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	select {
	case received := <-targetReceived:
		if !bytes.Equal(received, clientPayload) {
			t.Fatalf("target received corrupted payload: got %v, want %v", received, clientPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for target to receive payload")
	}

	// Read response back from cConn
	respBuf := make([]byte, 64)
	n, err = cConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read from proxy client failed: %v", err)
	}
	if string(respBuf[:n]) != "TARGET_RAW_RESPONSE" {
		t.Fatalf("expected 'TARGET_RAW_RESPONSE', got %q", string(respBuf[:n]))
	}
}

// TestAgentHandleProxy_NoProxyResponseOnError verifies that validation and connection failures
// cleanly close the stream without polluting it with ProxyResponse JSON.
func TestAgentHandleProxy_NoProxyResponseOnError(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	// Case 1: Restricted cloud metadata IP
	sConn1, cConn1 := net.Pipe()
	req1 := protocol.ProxyRequest{
		TargetHost: "169.254.169.254",
		TargetPort: 80,
	}
	env1, _ := json.Marshal(req1)

	go ag.HandleProxy(sConn1, env1)

	buf1 := make([]byte, 256)
	n1, err1 := cConn1.Read(buf1)
	if n1 > 0 {
		t.Fatalf("HandleProxy wrote %d bytes on validation error: %q (must not write JSON on data stream)", n1, string(buf1[:n1]))
	}
	if err1 == nil {
		t.Fatalf("expected EOF / stream close on validation error")
	}
	cConn1.Close()

	// Case 2: Unreachable / closed target port
	sConn2, cConn2 := net.Pipe()
	req2 := protocol.ProxyRequest{
		TargetHost: "127.0.0.1",
		TargetPort: 65432, // Unused port
	}
	env2, _ := json.Marshal(req2)

	go ag.HandleProxy(sConn2, env2)

	buf2 := make([]byte, 256)
	n2, err2 := cConn2.Read(buf2)
	if n2 > 0 {
		t.Fatalf("HandleProxy wrote %d bytes on dial error: %q (must not write JSON on data stream)", n2, string(buf2[:n2]))
	}
	if err2 == nil {
		t.Fatalf("expected EOF / stream close on dial error")
	}
	cConn2.Close()
}


func TestAgentContextCancellation(t *testing.T) {
	dnsMgr := meshdns.NewSystemDNSManager("fabric.mesh")
	ag := New(Config{
		ServerURL:    "wss://127.0.0.1:65530/ws",
		Domain:       "fabric.mesh",
		Token:        "tok",
		Hostname:     "node-canceler",
		DNSManager:   dnsMgr,
		InitialRetry: 20 * time.Millisecond,
		MaxBackoff:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- ag.Run(ctx)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil on context cancel, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("agent did not terminate cleanly on context cancellation")
	}
}

func TestAgentHandleExecUserValidation(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	maliciousUsers := []string{
		"root; echo pwned",
		"user\" -c \"whoami",
		"$USER",
		"user\nname",
		"user`id`",
		"-badflag",
	}

	for _, badUser := range maliciousUsers {
		sConn, cConn := net.Pipe()

		req := protocol.ExecRequest{
			Command: "echo test",
			User:    badUser,
		}
		env, _ := json.Marshal(req)

		go ag.HandleExec(sConn, env)

		var stderrCaptured []byte
		var exitCode string

		for {
			frame, err := protocol.ReadFrame(cConn)
			if err != nil {
				break
			}
			if frame.Type == protocol.StreamStderr {
				stderrCaptured = append(stderrCaptured, frame.Payload...)
			}
			if frame.Type == protocol.StreamExit {
				exitCode = string(frame.Payload)
			}
		}
		cConn.Close()

		if exitCode != "1" {
			t.Errorf("expected exit code 1 for invalid user %q, got %q", badUser, exitCode)
		}
		if len(stderrCaptured) == 0 {
			t.Errorf("expected error output on stderr for invalid user %q", badUser)
		}
	}
}

func TestAgentCheckOrigin(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	validOrigins := []struct {
		origin string
		host   string
	}{
		{"", "127.0.0.1:8080"},
		{"http://localhost:8080", "127.0.0.1:8080"},
		{"http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"http://test-node.fabric.mesh:8080", "test-node.fabric.mesh:8080"},
		{"https://fabric.mesh", "fabric.mesh"},
		{"http://samehost.local:8080", "samehost.local:8080"},
	}

	for _, tc := range validOrigins {
		req, _ := http.NewRequest("GET", "/ws", nil)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		req.Host = tc.host
		if !ag.CheckOrigin(req) {
			t.Errorf("expected CheckOrigin to accept origin=%q with host=%q", tc.origin, tc.host)
		}
	}

	invalidOrigins := []struct {
		origin string
		host   string
	}{
		{"http://evil.com", "node1.fabric.mesh:8080"},
		{"https://malicious-site.org", "127.0.0.1:8080"},
		{"http://attacker.mesh.com", "node1.fabric.mesh:8080"},
	}

	for _, tc := range invalidOrigins {
		req, _ := http.NewRequest("GET", "/ws", nil)
		req.Header.Set("Origin", tc.origin)
		req.Host = tc.host
		if ag.CheckOrigin(req) {
			t.Errorf("expected CheckOrigin to reject origin=%q with host=%q", tc.origin, tc.host)
		}
	}
}

func TestAgentHandleExecStreamCloseKillsProcessGroup(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	serverConn, clientConn := net.Pipe()

	// Launch a long-running process that prints its PID and sleeps
	req := protocol.ExecRequest{
		Command: "echo $$; sleep 100",
	}
	env, _ := json.Marshal(req)

	doneCh := make(chan struct{})
	go func() {
		ag.HandleExec(serverConn, env)
		close(doneCh)
	}()

	// Read the PID from stdout
	frame, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("failed to read PID frame: %v", err)
	}
	if frame.Type != protocol.StreamStdout {
		t.Fatalf("expected stdout frame, got type %d", frame.Type)
	}

	pidStr := strings.TrimSpace(string(frame.Payload))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		t.Fatalf("failed to parse child PID from %q: %v", pidStr, err)
	}

	// Verify child process is running
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("process %d is not running: %v", pid, err)
	}

	// Close client connection
	clientConn.Close()

	// Wait for HandleExec to complete and verify process is killed within 1s
	select {
	case <-doneCh:
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("HandleExec did not terminate within 1.5s after stream close")
	}

	// Process should no longer exist
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("process %d is still alive after stream closure", pid)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func TestFormatEnvExports(t *testing.T) {
	env := []string{
		"VALID=hello world",
		"QUOTED=it's 'great'",
		"INVALID-KEY=blocked",
		"INJECTION=val; rm -rf /",
		"JUST_KEY",
		"LD_PRELOAD=/tmp/evil.so",
		"IFS=:",
	}

	result := formatEnvExports(env)
	expected := "export VALID='hello world'\nexport QUOTED='it'\\''s '\\''great'\\'''\nexport INJECTION='val; rm -rf /'\nexport JUST_KEY\n"
	if result != expected {
		t.Fatalf("expected:\n%q\ngot:\n%q", expected, result)
	}
}

func TestSanitizeEnv_BlockedKeys(t *testing.T) {
	input := []string{
		"SAFE_VAR=value",
		"LD_PRELOAD=/malicious.so",
		"LD_LIBRARY_PATH=/tmp/lib",
		"IFS=\t",
		"BASH_ENV=/tmp/exec",
		"ENV=/tmp/exec",
		"NODE_OPTIONS=--require /tmp/malicious.js",
		"BAD.KEY=123",
		"123BAD=456",
		"ANOTHER_GOOD=789",
	}

	cleaned := SanitizeEnv(input)
	if len(cleaned) != 2 {
		t.Fatalf("expected 2 sanitized vars, got %d: %v", len(cleaned), cleaned)
	}
	if cleaned[0] != "SAFE_VAR=value" || cleaned[1] != "ANOTHER_GOOD=789" {
		t.Errorf("unexpected sanitized output: %v", cleaned)
	}
}

func TestHandleExec_TimeoutBoundary(t *testing.T) {
	ag := New(Config{
		Domain:   "fabric.mesh",
		Hostname: "test-node",
	})

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	req := protocol.ExecRequest{
		Command:        "sleep 10",
		TimeoutSeconds: 1, // 1 second timeout
	}
	env, _ := json.Marshal(req)

	doneCh := make(chan struct{})
	go func() {
		ag.HandleExec(serverConn, env)
		close(doneCh)
	}()

	start := time.Now()
	// Read frames until exit or EOF
	var stderrBuf bytes.Buffer
	for {
		frame, err := protocol.ReadFrame(clientConn)
		if err != nil {
			break
		}
		if frame.Type == protocol.StreamStderr {
			stderrBuf.Write(frame.Payload)
		}
		if frame.Type == protocol.StreamExit {
			break
		}
	}

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("HandleExec did not terminate within timeout window")
	}

	elapsed := time.Since(start)
	if elapsed > 2500*time.Millisecond {
		t.Errorf("HandleExec took too long: %v (expected ~1s)", elapsed)
	}
	if !strings.Contains(stderrBuf.String(), "timed out") {
		t.Errorf("expected timeout notice in stderr, got: %q", stderrBuf.String())
	}
}





