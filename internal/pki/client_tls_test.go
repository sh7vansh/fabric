package pki_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"fabric/internal/pki"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		input       string
		expected    string
		expectScheme string
	}{
		{"localhost:8080/ws", "ws://localhost:8080/ws", "ws"},
		{"ws://localhost:8080/ws", "ws://localhost:8080/ws", "ws"},
		{"ws://localhost:443/ws", "wss://localhost:443/ws", "wss"},
		{"ws://localhost:8443/ws", "wss://localhost:8443/ws", "wss"},
		{"http://example.com:443/api", "https://example.com:443/api", "https"},
		{"wss://example.com/ws", "wss://example.com/ws", "wss"},
	}

	for _, c := range cases {
		u, err := pki.NormalizeURL(c.input)
		if err != nil {
			t.Fatalf("NormalizeURL(%q) failed: %v", c.input, err)
		}
		if u.Scheme != c.expectScheme {
			t.Errorf("NormalizeURL(%q) scheme = %q, expected %q", c.input, u.Scheme, c.expectScheme)
		}
	}
}

func TestLiveWSSHandshake(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-wss-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.mesh")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, ca.TLSConfig())
	defer tlsLn.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.TextMessage, []byte("hello-secure-mesh"))
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(tlsLn)
	defer srv.Close()

	caCertPath := filepath.Join(tmpDir, "ca.crt")
	dialer, err := pki.NewWSSDialer(caCertPath)
	if err != nil {
		t.Fatalf("NewWSSDialer failed: %v", err)
	}

	wssURL := fmt.Sprintf("wss://%s/ws", ln.Addr().String())
	conn, _, err := dialer.Dial(wssURL, nil)
	if err != nil {
		t.Fatalf("WSS Dial failed: %v", pki.FormatTLSError(err))
	}
	defer conn.Close()

	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if string(msg) != "hello-secure-mesh" {
		t.Errorf("unexpected message: %q", string(msg))
	}
}
