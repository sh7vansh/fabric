package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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

func TestAgentContextCancellation(t *testing.T) {
	dnsMgr := meshdns.NewSystemDNSManager("fabric.mesh")
	ag := New(Config{
		ServerURL:    "ws://127.0.0.1:65530/ws",
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
