package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"fabric/internal/agent"
	"fabric/internal/pki"
	"fabric/internal/relay"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s to become ready", addr)
}

func setupTestPKI(t *testing.T) (string, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "fabric-port-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.test")
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to init test CA: %v", err)
	}

	clientCert, err := ca.MintCertificate([]string{"cli.fabric.test", "127.0.0.1"}, time.Hour)
	if err != nil {
		os.RemoveAll(tmpDir)
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

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}
	return tmpDir, cleanup
}

func setupTestPKIAndAgent(t *testing.T, hostname string) (string, string, func()) {
	t.Helper()
	tmpDir, pkiCleanup := setupTestPKI(t)

	ag := agent.New(agent.Config{
		ServerURL:     "wss://dummy",
		ListenAddress: "127.0.0.1:0",
		Domain:        "fabric.test",
		Hostname:      hostname,
		Token:         "test-token",
		CACertPath:    tmpDir + "/ca.crt",
	})

	ctx, cancel := context.WithCancel(context.Background())

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
		cancel()
		pkiCleanup()
		t.Fatalf("agent listener failed to start")
	}

	cleanup := func() {
		cancel()
		pkiCleanup()
	}

	return tmpDir, listenAddr, cleanup
}

func TestPortForwarding_PlainTCP(t *testing.T) {
	tmpDir, listenAddr, cleanup := setupTestPKIAndAgent(t, "direct-aizen")
	defer cleanup()

	// 1. Start a plain TCP echo server simulating a backend service on the node
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Configure CLI client
	localPort := getFreePort(t)
	cfg := &Config{
		Host:   "wss://dummy:9999/ws",
		Token:  "test-token",
		CACert: tmpDir + "/ca.crt",
		DirectNodes: map[string]DirectNodeEntry{
			"direct-aizen": {
				Address:      listenAddr,
				Tags:         []string{"inverted"},
				RegisteredAt: time.Now().UTC(),
			},
		},
	}
	client := NewClient(cfg)

	// 3. Start port forwarding: localPort -> direct-aizen:echoPort
	go func() {
		_ = client.ForwardPort("direct-aizen", localPort, echoPort)
	}()

	if err := waitForPort(fmt.Sprintf("127.0.0.1:%d", localPort), 3*time.Second); err != nil {
		t.Fatalf("forwarded port failed to open: %v", err)
	}

	// 4. Connect to forwarded port and send arbitrary binary and text data
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatalf("failed to dial forwarded port: %v", err)
	}
	defer conn.Close()

	payload := []byte{0x00, 0xFF, 0x13, 0x37, 'F', 'A', 'B', 'R', 'I', 'C', '_', 'T', 'C', 'P', '\n'}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write to forwarded connection: %v", err)
	}

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("failed to read from forwarded connection: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Fatalf("echo mismatch: got %v, want %v", received, payload)
	}
}

func TestPortForwarding_HTTPS_NPM_SNI(t *testing.T) {
	tmpDir, listenAddr, cleanup := setupTestPKIAndAgent(t, "direct-aizen")
	defer cleanup()

	// 1. Mint TLS cert for gloria.pomogranate.lol from the test CA
	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.test")
	if err != nil {
		t.Fatalf("failed to load CA: %v", err)
	}

	serverCert, err := ca.MintCertificate([]string{"gloria.pomogranate.lol", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("failed to mint server cert: %v", err)
	}

	// 2. Start an HTTPS server simulating NPM (Nginx Proxy Manager) on the node
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Verify SNI reached the server
		if r.TLS != nil && r.TLS.ServerName == "gloria.pomogranate.lol" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("gloria browser ui"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("unknown vhost"))
	})

	tlsServerLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	})
	if err != nil {
		t.Fatalf("failed to start TLS server: %v", err)
	}
	defer tlsServerLn.Close()
	npmPort := tlsServerLn.Addr().(*net.TCPAddr).Port

	server := &http.Server{
		Handler: mux,
	}
	go server.Serve(tlsServerLn)
	defer server.Close()

	// 3. Configure CLI client
	localPort := getFreePort(t)
	cfg := &Config{
		Host:   "wss://dummy:9999/ws",
		Token:  "test-token",
		CACert: tmpDir + "/ca.crt",
		DirectNodes: map[string]DirectNodeEntry{
			"direct-aizen": {
				Address:      listenAddr,
				Tags:         []string{"inverted"},
				RegisteredAt: time.Now().UTC(),
			},
		},
	}
	client := NewClient(cfg)

	// 4. Start port forwarding: localPort -> direct-aizen:npmPort
	go func() {
		_ = client.ForwardPort("direct-aizen", localPort, npmPort)
	}()

	if err := waitForPort(fmt.Sprintf("127.0.0.1:%d", localPort), 3*time.Second); err != nil {
		t.Fatalf("forwarded port failed to open: %v", err)
	}

	// 5. Simulate curl -vk --resolve gloria.pomogranate.lol:8444:127.0.0.1 https://gloria.pomogranate.lol:8444/
	caCertPEM, err := os.ReadFile(tmpDir + "/ca.crt")
	if err != nil {
		t.Fatalf("failed to read ca.crt: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Resolve gloria.pomogranate.lol to 127.0.0.1:<localPort>
				return net.Dial(network, fmt.Sprintf("127.0.0.1:%d", localPort))
			},
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				ServerName: "gloria.pomogranate.lol",
			},
		},
		Timeout: 5 * time.Second,
	}

	reqURL := fmt.Sprintf("https://gloria.pomogranate.lol:%d/", localPort)
	resp, err := httpClient.Get(reqURL)
	if err != nil {
		t.Fatalf("HTTPS GET through port forward failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 OK, got %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != "gloria browser ui" {
		t.Errorf("expected body 'gloria browser ui', got %q", string(body))
	}

	// 6. Direct TLS ClientHandshake test to strictly verify no non-TLS bytes are present
	rawConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatalf("failed to dial forwarded port: %v", err)
	}
	defer rawConn.Close()

	tlsClient := tls.Client(rawConn, &tls.Config{
		RootCAs:    certPool,
		ServerName: "gloria.pomogranate.lol",
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("raw TLS handshake failed (stream corruption check): %v", err)
	}

	state := tlsClient.ConnectionState()
	if !state.HandshakeComplete {
		t.Errorf("TLS handshake not complete")
	}
	if state.ServerName != "gloria.pomogranate.lol" {
		t.Errorf("expected ServerName 'gloria.pomogranate.lol', got %q", state.ServerName)
	}
}

func TestPortForwarding_RelayMode(t *testing.T) {
	// Test transparent port forwarding routed through central MeshRelay control plane
	tmpDir, cleanup := setupTestPKI(t)
	defer cleanup()

	// 1. Start Relay
	r := relay.New(relay.Config{
		Domain: "fabric.test",
		Token:  "test-token",
	})
	defer r.Close()

	relayMux := http.NewServeMux()
	upgrader := r.Upgrader()
	relayMux.HandleFunc("/ws", func(w http.ResponseWriter, req *http.Request) {
		authHeader := req.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		authenticated := r.ValidateToken(token)

		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		go r.ServeWSAuth(conn, req.RemoteAddr, authenticated)
	})

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.test")
	if err != nil {
		t.Fatalf("failed to init CA: %v", err)
	}

	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start relay listener: %v", err)
	}
	defer relayLn.Close()
	relayPort := relayLn.Addr().(*net.TCPAddr).Port

	tlsRelayLn := tls.NewListener(relayLn, ca.TLSConfig())
	defer tlsRelayLn.Close()

	relayServer := &http.Server{Handler: relayMux}
	go relayServer.Serve(tlsRelayLn)
	defer relayServer.Close()

	// 2. Start Agent connected to Relay
	ag := agent.New(agent.Config{
		ServerURL:     fmt.Sprintf("wss://127.0.0.1:%d/ws", relayPort),
		Domain:        "fabric.test",
		Hostname:      "node-relay-1",
		Token:         "test-token",
		CACertPath:    tmpDir + "/ca.crt",
		InitialRetry: 20 * time.Millisecond,
		MaxBackoff:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ag.Run(ctx)
	}()

	// Wait for node to register in relay
	registered := false
	for i := 0; i < 50; i++ {
		if _, ok := r.GetNode("node-relay-1"); ok {
			registered = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !registered {
		t.Fatalf("node failed to register with relay")
	}

	// 3. Start echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 4. Configure CLI client pointing to Relay WebSocket and run ForwardPort
	localPort := getFreePort(t)
	cfg := &Config{
		Host:   fmt.Sprintf("wss://127.0.0.1:%d/ws", relayPort),
		Token:  "test-token",
		CACert: tmpDir + "/ca.crt",
	}
	client := NewClient(cfg)

	go func() {
		_ = client.ForwardPort("node-relay-1", localPort, echoPort)
	}()

	if err := waitForPort(fmt.Sprintf("127.0.0.1:%d", localPort), 3*time.Second); err != nil {
		t.Fatalf("forwarded port failed to open: %v", err)
	}

	// 5. Test raw data exchange through relay-routed tunnel
	clientConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatalf("failed to dial forwarded port: %v", err)
	}
	defer clientConn.Close()

	testMsg := []byte("RELAY_ROUTED_TRANSPARENT_STREAM_TEST")
	if _, err := clientConn.Write(testMsg); err != nil {
		t.Fatalf("failed to write to tunnel: %v", err)
	}

	respBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, respBuf); err != nil {
		t.Fatalf("failed to read from tunnel: %v", err)
	}

	if !bytes.Equal(respBuf, testMsg) {
		t.Fatalf("relay port forward mismatch: got %q, want %q", string(respBuf), string(testMsg))
	}
}

