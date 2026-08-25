package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"fabric/internal/agent"
	"fabric/internal/pki"
)

func TestInvertedConnectionMode(t *testing.T) {
	// 1. Setup temporary directory for test PKI
	tmpDir, err := os.MkdirTemp("", "fabric-direct-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.test")
	if err != nil {
		t.Fatalf("failed to init test CA: %v", err)
	}

	// Mint a single certificate valid for both client auth and server auth (for 127.0.0.1)
	clientCert, err := ca.MintCertificate([]string{"cli.fabric.test", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("failed to mint client cert: %v", err)
	}
	// Extract the PEM blocks
	var certPEM, keyPEM []byte
	for _, c := range clientCert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(clientCert.PrivateKey.(*ecdsa.PrivateKey))
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	os.WriteFile(tmpDir+"/client.crt", certPEM, 0644)
	os.WriteFile(tmpDir+"/client.key", keyPEM, 0600)

	// 2. Start Agent daemon with Inverted Connection Mode enabled on dynamic port
	ag := agent.New(agent.Config{
		ServerURL:     "ws://dummy",
		ListenAddress: "127.0.0.1:0", // dynamic port
		Domain:        "fabric.test",
		Hostname:      "test-node",
		Token:         "test-token",
		CACertPath:    tmpDir + "/ca.crt",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ag.ListenAndServe(ctx)
	}()

	// Wait for listener to bind and update its ListenAddress
	var listenAddr string
	for i := 0; i < 50; i++ {
		addr := ag.ListenAddr()
		if addr != "" && addr != "127.0.0.1:0" {
			listenAddr = addr
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatalf("agent listener failed to start")
	}

	// 3. Configure CLI Client
	cfg := &Config{
		Host:          "wss://dummy",
		Token:         "test-token",
		CACert:        tmpDir + "/ca.crt",
		DirectAddress: listenAddr,
	}
	client := NewClient(cfg)

	// 4. Test Exec (echo command)
	opts := ExecOptions{
		Target:      "test-node",
		Command:     "echo 'direct-mode-works'",
		AllocatePTY: false,
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, err = client.Execute(opts, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("direct execute failed: %v", err)
	}

	outStr := stdout.String()
	if outStr != "direct-mode-works\n" {
		t.Errorf("expected 'direct-mode-works', got %q", outStr)
	}
}

func TestTransparentDirectRoutingAndNodeListing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-transparent-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.test")
	if err != nil {
		t.Fatalf("failed to init test CA: %v", err)
	}

	clientCert, err := ca.MintCertificate([]string{"cli.fabric.test", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("failed to mint client cert: %v", err)
	}
	var certPEM, keyPEM []byte
	for _, c := range clientCert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(clientCert.PrivateKey.(*ecdsa.PrivateKey))
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	os.WriteFile(tmpDir+"/client.crt", certPEM, 0644)
	os.WriteFile(tmpDir+"/client.key", keyPEM, 0600)

	ag := agent.New(agent.Config{
		ServerURL:     "ws://dummy",
		ListenAddress: "127.0.0.1:0",
		Domain:        "fabric.test",
		Hostname:      "inv-node-1",
		Token:         "test-token",
		CACertPath:    tmpDir + "/ca.crt",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ag.ListenAndServe(ctx)
	}()

	var listenAddr string
	for i := 0; i < 50; i++ {
		addr := ag.ListenAddr()
		if addr != "" && addr != "127.0.0.1:0" {
			listenAddr = addr
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatalf("agent listener failed to start")
	}

	// 1. Configure CLI with DirectNodes registry (no explicit DirectAddress)
	cfg := &Config{
		Host:   "wss://dummy-unreachable-socket:9999/ws",
		Token:  "test-token",
		CACert: tmpDir + "/ca.crt",
		DirectNodes: map[string]DirectNodeEntry{
			"inv-node-1": {
				Address:      listenAddr,
				Tags:         []string{"remote", "gpu"},
				RegisteredAt: time.Now().UTC(),
			},
		},
	}
	client := NewClient(cfg)

	// 2. Transparent Execution (targets inv-node-1, routes directly to listenAddr)
	opts := ExecOptions{
		Target:      "inv-node-1",
		Command:     "echo 'transparent-routing-success'",
		AllocatePTY: false,
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, err = client.Execute(opts, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("transparent direct execute failed: %v", err)
	}

	outStr := stdout.String()
	if outStr != "transparent-routing-success\n" {
		t.Errorf("expected 'transparent-routing-success', got %q", outStr)
	}

	// 3. Test ListNodes merging direct nodes and prepending socket
	nodes, err := client.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes failed: %v", err)
	}

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes (socket + direct node) in ListNodes, got %d", len(nodes))
	}
	if nodes[0].ID != "socket" {
		t.Errorf("expected first node to be 'socket', got %s", nodes[0].ID)
	}
	if nodes[1].Hostname != "inv-node-1" {
		t.Errorf("expected hostname 'inv-node-1', got %s", nodes[1].Hostname)
	}
	if nodes[1].Status != "online [MODE: remote]" {
		t.Errorf("expected status 'online [MODE: remote]', got %s", nodes[1].Status)
	}
}

