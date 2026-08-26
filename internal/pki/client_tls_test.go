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
	validCases := []struct {
		input        string
		expectScheme string
	}{
		{"localhost:8443/ws", "wss"},
		{"localhost:8080/ws", "wss"},
		{"wss://localhost:8443/ws", "wss"},
		{"https://example.com:443/api", "https"},
		{"wss://example.com/ws", "wss"},
		{"192.168.1.50:8443/ws", "wss"},
	}

	for _, c := range validCases {
		u, err := pki.NormalizeURL(c.input)
		if err != nil {
			t.Fatalf("NormalizeURL(%q) unexpectedly failed: %v", c.input, err)
		}
		if u.Scheme != c.expectScheme {
			t.Errorf("NormalizeURL(%q) scheme = %q, expected %q", c.input, u.Scheme, c.expectScheme)
		}
	}

	invalidCases := []string{
		"ws://localhost:8080/ws",
		"http://localhost:8080/api",
		"ftp://localhost:21",
	}

	for _, raw := range invalidCases {
		_, err := pki.NormalizeURL(raw)
		if err == nil {
			t.Errorf("NormalizeURL(%q) expected error for unencrypted/unsupported scheme, got nil", raw)
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

func TestFederationSecureDialer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-fed-dialer-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caCertPath := filepath.Join(tmpDir, "fed-ca.crt")
	os.WriteFile(caCertPath, []byte("invalid-ca-data"), 0644)

	// Should fail cleanly on invalid CA
	_, err = pki.NewFederationSecureDialer(caCertPath, nil)
	if err == nil {
		t.Errorf("expected error building federation dialer with invalid CA, got nil")
	}
}

