package tlsengine_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"fabric/internal/tlsengine"
)

func TestEngineInternalCARouting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-engine-ca-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	engine, err := tlsengine.New(tlsengine.Config{
		CADir:        tmpDir,
		MeshDomain:   "fabric.mesh",
		PublicDomain: "example.com",
		ActiveNodes: func() []string {
			return []string{"worker-1", "worker-2"}
		},
	})
	if err != nil {
		t.Fatalf("tlsengine.New failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, engine.TLSConfig())
	defer tlsLn.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "tls engine mesh response")
		}),
	}
	go srv.Serve(tlsLn)
	defer srv.Close()

	// Connect with client trusting internal CA
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: engine.CA().CertPool(),
			},
		},
	}

	serverURL := fmt.Sprintf("https://%s", ln.Addr().String())
	resp, err := client.Get(serverURL)
	if err != nil {
		t.Fatalf("GET %s failed: %v", serverURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "tls engine mesh response\n" {
		t.Errorf("unexpected body: %q", string(body))
	}
}

func TestHTTPSRedirectHandler(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-redirect-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	engine, err := tlsengine.New(tlsengine.Config{
		CADir:      tmpDir,
		MeshDomain: "fabric.mesh",
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := engine.HTTPSRedirectHandler(443)
	req := httptest.NewRequest("GET", "http://worker-1.fabric.mesh/api/status", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected status 301, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "https://worker-1.fabric.mesh/api/status" {
		t.Errorf("expected location 'https://worker-1.fabric.mesh/api/status', got %q", location)
	}
}
