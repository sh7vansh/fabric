package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fabric/internal/pki"
	"fabric/internal/server"
)

func TestServerInProcessTLSEndToEnd(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-server-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	srv, err := server.New(server.Config{
		Domain:     "fabric.test",
		Port:       8443,
		CADir:      caDir,
		Token:      "secret-token-123",
		AdminToken: "admin-token-456",
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	defer srv.Close()

	// Spin up ephemeral TLS listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		_ = srv.ServeTLS(ln)
	}()

	serverPort := ln.Addr().(*net.TCPAddr).Port
	caCertPath := filepath.Join(caDir, "ca.crt")

	// 1. Verify WSS WebSocket dial over Strict TLS with SecureDialer
	dialer, err := pki.NewSecureDialer(caCertPath)
	if err != nil {
		t.Fatalf("NewSecureDialer failed: %v", err)
	}

	wssURL := fmt.Sprintf("wss://127.0.0.1:%d/ws", serverPort)
	header := http.Header{}
	header.Add("Authorization", "Bearer secret-token-123")

	conn, _, err := dialer.Dial(wssURL, header)
	if err != nil {
		t.Fatalf("WSS Dial failed: %v", err)
	}
	defer conn.Close()

	// 2. Verify HTTPS REST /version endpoint over TLS
	tlsCfg, err := pki.BuildMTLSConfig(caCertPath)
	if err != nil {
		t.Fatalf("BuildMTLSConfig failed: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/version", serverPort))
	if err != nil {
		t.Fatalf("GET /version failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var verMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &verMap); err != nil {
		t.Fatalf("invalid json from /version: %v", err)
	}

	if verMap["role"] != "server" {
		t.Errorf("expected role 'server', got %v", verMap["role"])
	}
	if verMap["domain"] != "fabric.test" {
		t.Errorf("expected domain 'fabric.test', got %v", verMap["domain"])
	}
}

func TestServerGracefulShutdown(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-server-shutdown-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	srv, err := server.New(server.Config{
		Domain: "fabric.test",
		Port:   65431,
		CADir:  caDir,
		Token:  "test-token",
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected clean shutdown on context cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("server did not stop in time on cancel")
	}
}
