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

	// Mint a client cert
	clientCert, err := ca.MintCertificate([]string{"cli.fabric.test"}, time.Hour)
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

	// 2. Start Agent daemon with Inverted Connection Mode enabled
	listenAddr := "127.0.0.1:0"
	ag := agent.New(agent.Config{
		ServerURL:     "ws://dummy",
		ListenAddress: listenAddr,
		Domain:        "fabric.test",
		Hostname:      "test-node",
		Token:         "test-token",
		CACertPath:    tmpDir + "/ca.crt",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a fixed port or find an open port.
	// We'll let it try to bind to a high port or we can just give it a specific port.
	// Actually, 127.0.0.1:0 will choose a random port but how do we know which port?
	// The agent config takes a string. Let's just use a high port.
	listenAddr = "127.0.0.1:48123"
	ag = agent.New(agent.Config{
		ServerURL:     "ws://dummy",
		ListenAddress: listenAddr,
		Domain:        "fabric.test",
		Hostname:      "test-node",
		Token:         "test-token",
		CACertPath:    tmpDir + "/ca.crt",
	})

	go func() {
		ag.ListenAndServe(ctx)
	}()

	// Wait for listener to start
	time.Sleep(500 * time.Millisecond)

	// 3. Configure CLI Client
	cfg := &Config{
		Host:   "wss://dummy",
		Token:  "test-token",
		CACert: tmpDir + "/ca.crt",
	}
	client := NewClient(cfg)
	client.DirectAddress = listenAddr

	// 4. Test Exec (echo command)
	opts := ExecOptions{
		Target:      "test-node",
		Command:     "echo 'direct-mode-works'",
		AllocatePTY: false,
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = client.Execute(opts, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("direct execute failed: %v", err)
	}

	outStr := stdout.String()
	if outStr != "direct-mode-works\n" {
		t.Errorf("expected 'direct-mode-works', got %q", outStr)
	}
}
