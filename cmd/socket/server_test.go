package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"fabric/internal/cli"
	"fabric/internal/protocol"
	"fabric/internal/relay"

	"github.com/gorilla/websocket"
)

func setupTestServer(testToken string) (*httptest.Server, *websocket.Dialer, *relay.Relay, string) {
	meshRelay := relay.New(relay.Config{
		Domain:   "fabric.mesh",
		Token:    testToken,
		PingFreq: 0,
	})

	mux := http.NewServeMux()

	upgrader := meshRelay.Upgrader()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var provided string
		if strings.HasPrefix(authHeader, "Bearer ") {
			provided = strings.TrimPrefix(authHeader, "Bearer ")
		}
		authenticated := meshRelay.ValidateToken(provided)

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		go func() {
			_ = meshRelay.ServeWSAuth(conn, r.RemoteAddr, authenticated)
		}()
	})

	authenticate := func(w http.ResponseWriter, r *http.Request) bool {
		authHeader := r.Header.Get("Authorization")
		var provided string
		if strings.HasPrefix(authHeader, "Bearer ") {
			provided = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if !meshRelay.ValidateToken(provided) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meshRelay.ListNodes())
	})

	server := httptest.NewTLSServer(mux)
	certPool := x509.NewCertPool()
	certPool.AddCert(server.Certificate())

	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}

	// Write cert PEM to temp file for client
	tmpFile, _ := os.CreateTemp("", "ca-*.crt")
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}
	_ = os.WriteFile(tmpFile.Name(), pem.EncodeToMemory(pemBlock), 0644)
	tmpFile.Close()

	return server, dialer, meshRelay, tmpFile.Name()
}

func TestServerHTTPAuth(t *testing.T) {
	testToken := "test-secret-token-123"
	ts, _, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	// 1. Unauthorized request
	resp, err := ts.Client().Get(ts.URL + "/nodes")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Authorized request
	req, _ := http.NewRequest("GET", ts.URL+"/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp2, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("HTTP GET with auth failed: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestServerWebSocketHandshakeAuthAndReconnect(t *testing.T) {
	testToken := "test-secret-token-123"
	ts, dialer, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	wsURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"

	// 1. Handshake with invalid token
	conn1, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	mux1, err := protocol.NewStreamMultiplexer(conn1, false)
	if err != nil {
		t.Fatalf("client mux failed: %v", err)
	}
	stream1, _ := mux1.Session.Open()
	badHs := protocol.Handshake{
		Type:      protocol.TypeHandshake,
		SessionID: "sess-bad",
		Hostname:  "node-a",
		Token:     "wrong-token",
	}
	bBad, _ := json.Marshal(badHs)
	stream1.Write(bBad)
	stream1.Close()

	time.Sleep(50 * time.Millisecond)
	if !mux1.Session.IsClosed() {
		t.Errorf("expected bad token session to be closed")
	}
	conn1.Close()

	// 2. Handshake with valid token
	conn2, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	mux2, err := protocol.NewStreamMultiplexer(conn2, false)
	if err != nil {
		t.Fatalf("client mux failed: %v", err)
	}
	stream2, _ := mux2.Session.Open()
	goodHs := protocol.Handshake{
		Type:      protocol.TypeHandshake,
		SessionID: "sess-good-1",
		Hostname:  "node-a",
		Token:     testToken,
	}
	bGood, _ := json.Marshal(goodHs)
	stream2.Write(bGood)
	stream2.Close()

	time.Sleep(50 * time.Millisecond)
	if mux2.Session.IsClosed() {
		t.Errorf("expected valid token session to stay open")
	}

	// 3. Reconnect / Renewal: Reconnecting with same hostname seamlessly renews and displaces old session
	conn3, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	mux3, err := protocol.NewStreamMultiplexer(conn3, false)
	if err != nil {
		t.Fatalf("client mux failed: %v", err)
	}
	stream3, _ := mux3.Session.Open()
	renewHs := protocol.Handshake{
		Type:      protocol.TypeHandshake,
		SessionID: "sess-good-2",
		Hostname:  "node-a",
		Token:     testToken,
	}
	bRenew, _ := json.Marshal(renewHs)
	stream3.Write(bRenew)
	stream3.Close()

	time.Sleep(50 * time.Millisecond)
	if mux3.Session.IsClosed() {
		t.Errorf("expected new reconnected session to stay open")
	}
	if !mux2.Session.IsClosed() {
		t.Errorf("expected displaced previous session to be closed")
	}

	conn2.Close()
	conn3.Close()
}

func TestServerMultiNodeParallelExecution(t *testing.T) {
	testToken := "secret-broadcast-token"
	ts, dialer, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	wsURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"

	// Connect Node 1 (worker-1, tags: [web, prod])
	conn1, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial node1 failed: %v", err)
	}
	defer conn1.Close()
	mux1, err := protocol.NewStreamMultiplexer(conn1, false)
	if err != nil {
		t.Fatalf("mux node1 failed: %v", err)
	}
	s1, _ := mux1.Session.Open()
	hs1 := protocol.Handshake{
		Type:     protocol.TypeHandshake,
		Hostname: "worker-1",
		Token:    testToken,
		Tags:     []string{"web", "prod"},
	}
	b1, _ := json.Marshal(hs1)
	s1.Write(b1)
	s1.Close()

	// Mock node1 agent stream handler
	go func() {
		for {
			stream, err := mux1.Session.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				protocol.WriteFrame(c, protocol.StreamStdout, []byte("output from worker-1\n"))
				protocol.WriteFrame(c, protocol.StreamExit, []byte("0"))
			}(stream)
		}
	}()

	// Connect Node 2 (worker-2, tags: [db, prod])
	conn2, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial node2 failed: %v", err)
	}
	defer conn2.Close()
	mux2, err := protocol.NewStreamMultiplexer(conn2, false)
	if err != nil {
		t.Fatalf("mux node2 failed: %v", err)
	}
	s2, _ := mux2.Session.Open()
	hs2 := protocol.Handshake{
		Type:     protocol.TypeHandshake,
		Hostname: "worker-2",
		Token:    testToken,
		Tags:     []string{"db", "prod"},
	}
	b2, _ := json.Marshal(hs2)
	s2.Write(b2)
	s2.Close()

	// Mock node2 agent stream handler (returns exit code 1)
	go func() {
		for {
			stream, err := mux2.Session.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				protocol.WriteFrame(c, protocol.StreamStderr, []byte("error on worker-2\n"))
				protocol.WriteFrame(c, protocol.StreamExit, []byte("1"))
			}(stream)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	nodes := r.ListNodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 registered nodes, got %d", len(nodes))
	}

	// Verify tag filtering
	var prodNodes []string
	for _, n := range nodes {
		for _, tag := range n.Tags {
			if tag == "prod" {
				prodNodes = append(prodNodes, n.Hostname)
			}
		}
	}
	if len(prodNodes) != 2 {
		t.Errorf("expected 2 prod nodes, got %d", len(prodNodes))
	}
}

func TestServerUnauthenticatedExecStreamRejected(t *testing.T) {
	testToken := "secret-cluster-token"
	ts, dialer, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	wsURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"

	// Connect without Authorization header
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		t.Fatalf("mux failed: %v", err)
	}

	// Directly attempt sending TypeExecRequest on unauthenticated session
	stream, err := mux.Session.Open()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	req := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
		TargetHostname: "worker-1",
		Command:        "echo pwned",
	}
	b, _ := json.Marshal(req)
	_, _ = stream.Write(b)

	// Stream should be closed and session should be terminated
	time.Sleep(50 * time.Millisecond)
	if !mux.Session.IsClosed() {
		t.Errorf("expected unauthenticated stream attempt to terminate the session")
	}
}

func TestServerCSWSHOriginRejection(t *testing.T) {
	testToken := "secret-cluster-token"
	ts, dialer, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	wsURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"

	// 1. Unauthorized origin should be rejected with 403 Forbidden
	headerBad := http.Header{}
	headerBad.Set("Origin", "http://evil-attacker-site.com")
	headerBad.Set("Authorization", "Bearer "+testToken)

	_, respBad, err := dialer.Dial(wsURL, headerBad)
	if err == nil {
		t.Errorf("expected dial to fail for unauthorized Origin header")
	}
	if respBad != nil && respBad.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden, got %d", respBad.StatusCode)
	}

	// 2. Allowed localhost / same-host Origin should succeed
	headerGood := http.Header{}
	headerGood.Set("Origin", ts.URL)
	headerGood.Set("Authorization", "Bearer "+testToken)

	connGood, respGood, err := dialer.Dial(wsURL, headerGood)
	if err != nil {
		t.Fatalf("expected dial to succeed for same-origin, got error: %v (resp: %+v)", err, respGood)
	}
	connGood.Close()
}

func TestServerEndToEndAuthenticatedLifecycle(t *testing.T) {
	testToken := "e2e-token-xyz"
	ts, dialer, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	wsURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"

	// Connect mock target node agent
	nodeConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial node failed: %v", err)
	}
	defer nodeConn.Close()

	nodeMux, err := protocol.NewStreamMultiplexer(nodeConn, false)
	if err != nil {
		t.Fatalf("node mux failed: %v", err)
	}

	// Send handshake
	hsStream, _ := nodeMux.Session.Open()
	hs := protocol.Handshake{
		Type:     protocol.TypeHandshake,
		Hostname: "target-node",
		Token:    testToken,
	}
	bHs, _ := json.Marshal(hs)
	hsStream.Write(bHs)
	hsStream.Close()

	// Mock node agent stream responder
	go func() {
		for {
			stream, err := nodeMux.Session.Accept()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close()
				buf := make([]byte, 1024)
				n, _ := s.Read(buf)
				var req protocol.ExecRequest
				if err := json.Unmarshal(buf[:n], &req); err == nil {
					protocol.WriteFrame(s, protocol.StreamStdout, []byte("echoed: "+req.Command+"\n"))
					protocol.WriteFrame(s, protocol.StreamExit, []byte("0"))
				}
			}(stream)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Now use CLI client with valid token to execute command
	cliCfg := &cli.Config{
		Host:   ts.URL,
		Token:  testToken,
		CACert: caCert,
	}
	client := cli.NewClient(cliCfg)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	res, err := client.Execute(cli.ExecOptions{
		Target:  "target-node",
		Command: "uname -a",
	}, nil, &stdoutBuf, &stderrBuf)

	if err != nil {
		t.Fatalf("client.Execute failed: %v", err)
	}

	if !res.Results[0].Success {
		t.Errorf("expected execution success, got: %+v", res.Results[0])
	}
	if !strings.Contains(stdoutBuf.String(), "echoed: uname -a") {
		t.Errorf("expected stdout 'echoed: uname -a', got: %q", stdoutBuf.String())
	}
}

func TestServerWebSocketOriginValidation(t *testing.T) {
	testToken := "test-origin-token"
	ts, dialer, r, caCert := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()
	defer os.Remove(caCert)

	wsURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"

	// 1. Dial with disallowed Origin header
	badHeader := http.Header{}
	badHeader.Set("Origin", "http://malicious-website.com")
	_, resp, err := dialer.Dial(wsURL, badHeader)
	if err == nil {
		t.Fatalf("expected dial with disallowed Origin to fail, but succeeded")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden for bad origin, got %d", resp.StatusCode)
	}

	// 2. Dial with allowed localhost Origin header
	goodHeader := http.Header{}
	goodHeader.Set("Origin", "http://localhost")
	conn, _, err := dialer.Dial(wsURL, goodHeader)
	if err != nil {
		t.Fatalf("expected dial with localhost Origin to succeed, got error: %v", err)
	}
	conn.Close()
}

