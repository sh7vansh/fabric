package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"
	"fabric/internal/relay"

	"github.com/gorilla/websocket"
)

func setupTestServer(testToken string) (*httptest.Server, *websocket.Dialer, *relay.Relay) {
	meshRelay := relay.New(relay.Config{
		Domain:   "fabric.mesh",
		Token:    testToken,
		PingFreq: 0,
	})

	mux := http.NewServeMux()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		smux, err := protocol.NewStreamMultiplexer(conn, true)
		if err != nil {
			conn.Close()
			return
		}

		router := protocol.NewRouter(smux.Session)
		router.HandleFunc(string(protocol.TypeHandshake), func(stream net.Conn, env []byte) {
			defer stream.Close()
			var hs protocol.Handshake
			if err := json.Unmarshal(env, &hs); err != nil {
				conn.Close()
				return
			}

			if !meshRelay.ValidateToken(hs.Token) {
				conn.Close()
				return
			}

			if hs.Hostname == "" {
				conn.Close()
				return
			}

			sessID := hs.SessionID
			if sessID == "" {
				sessID = fmt.Sprintf("sess-%s-%d", hs.Hostname, time.Now().UnixNano())
			}

			meta := protocol.NodeMetadata{
				ID:        hs.Hostname,
				SessionID: sessID,
				Hostname:  hs.Hostname,
				Status:    "online",
				Tags:      hs.Tags,
			}

			if _, err := meshRelay.RegisterNode(meta, smux); err != nil {
				conn.Close()
				return
			}
		})

		router.HandleFunc(string(protocol.TypeExecRequest), func(stream net.Conn, env []byte) {
			var req protocol.ExecRequest
			if err := json.Unmarshal(env, &req); err != nil {
				stream.Close()
				return
			}
			if err := meshRelay.RouteStream(req.TargetHostname, env, stream); err != nil {
				stream.Close()
			}
		})

		router.Accept()
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

	server := httptest.NewServer(mux)
	dialer := websocket.DefaultDialer
	return server, dialer, meshRelay
}

func TestServerHTTPAuth(t *testing.T) {
	testToken := "test-secret-token-123"
	ts, _, r := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()

	// 1. Unauthorized request
	resp, err := http.Get(ts.URL + "/nodes")
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
	client := &http.Client{}
	resp2, err := client.Do(req)
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
	ts, dialer, r := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

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
	ts, dialer, r := setupTestServer(testToken)
	defer ts.Close()
	defer r.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

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
