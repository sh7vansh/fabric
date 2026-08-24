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

	"github.com/gorilla/websocket"
)

func setupTestServer(testToken string) (*httptest.Server, *websocket.Dialer) {
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
			json.Unmarshal(env, &hs)

			if !protocol.ValidateToken(hs.Token, testToken) {
				conn.Close()
				return
			}

			if hs.Hostname == "" {
				conn.Close()
				return
			}

			nodesLock.Lock()
			if existing, exists := nodes[hs.Hostname]; exists {
				if existing.Mux != nil && existing.Mux != smux {
					go existing.Mux.Session.Close()
				}
			}

			sessID := hs.SessionID
			if sessID == "" {
				sessID = fmt.Sprintf("sess-%s-%d", hs.Hostname, time.Now().UnixNano())
			}

			nodes[hs.Hostname] = &NodeState{
				Mux: smux,
				Metadata: protocol.NodeMetadata{
					ID:        hs.Hostname,
					SessionID: sessID,
					Hostname:  hs.Hostname,
					Status:    "online",
				},
			}
			nodesLock.Unlock()

			go func() {
				<-smux.Session.CloseChan()
				nodesLock.Lock()
				if curr, ok := nodes[hs.Hostname]; ok && curr.Mux == smux {
					delete(nodes, hs.Hostname)
				}
				nodesLock.Unlock()
				conn.Close()
			}()
		})
		router.Accept()
	})

	authenticate := func(w http.ResponseWriter, r *http.Request) bool {
		authHeader := r.Header.Get("Authorization")
		var provided string
		if strings.HasPrefix(authHeader, "Bearer ") {
			provided = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if !protocol.ValidateToken(provided, testToken) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}
		nodesLock.RLock()
		defer nodesLock.RUnlock()
		var list []protocol.NodeMetadata
		for _, s := range nodes {
			list = append(list, s.Metadata)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	server := httptest.NewServer(mux)
	dialer := websocket.DefaultDialer
	return server, dialer
}

func TestServerHTTPAuth(t *testing.T) {
	testToken := "test-secret-token-123"
	ts, _ := setupTestServer(testToken)
	defer ts.Close()

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
	ts, dialer := setupTestServer(testToken)
	defer ts.Close()

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
