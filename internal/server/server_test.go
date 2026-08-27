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
	"strings"
	"testing"
	"time"

	"fabric/internal/pki"
	"fabric/internal/server"
	"fabric/internal/wireguard"
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

func TestServerCanonicalVocabularyRoutes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-server-vocab-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	srv, err := server.New(server.Config{
		Domain:     "fabric.test",
		Port:       8443,
		CADir:      caDir,
		Token:      "tok-123",
		AdminToken: "admin-tok-456",
		ServerID:   "srv-alpha",
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	defer srv.Close()

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

	// 1. Verify /version contains server_id
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/version", serverPort), nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /version failed: %v", err)
	}
	defer resp.Body.Close()
	var verMap map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&verMap)
	if verMap["server_id"] != "srv-alpha" {
		t.Errorf("expected server_id 'srv-alpha', got %v", verMap["server_id"])
	}

	// 2. Verify /threads endpoint exists (requires auth)
	reqAuth, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/threads", serverPort), nil)
	reqAuth.Header.Set("Authorization", "Bearer tok-123")
	respThreads, err := client.Do(reqAuth)
	if err != nil {
		t.Fatalf("GET /threads failed: %v", err)
	}
	defer respThreads.Body.Close()
	if respThreads.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK on /threads, got %d", respThreads.StatusCode)
	}
}

func TestServerPreUpgradeAccessControlAndRateLimiting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-server-auth-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	srv, err := server.New(server.Config{
		Domain:     "fabric.test",
		Port:       8443,
		CADir:      caDir,
		Token:      "cluster-secret-xyz",
		AdminToken: "admin-secret-xyz",
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	defer srv.Close()

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
	dialer, err := pki.NewSecureDialer(caCertPath)
	if err != nil {
		t.Fatalf("NewSecureDialer failed: %v", err)
	}

	wssURL := fmt.Sprintf("wss://127.0.0.1:%d/ws", serverPort)

	// 1. Connection without token: must be rejected with 401 Unauthorized before WebSocket upgrade
	_, resp, err := dialer.Dial(wssURL, nil)
	if err == nil {
		t.Fatalf("expected dial without token to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}

	// 2. Connection with wrong token: must be rejected with 401 Unauthorized
	badHeader := http.Header{}
	badHeader.Set("Authorization", "Bearer wrong-token")
	_, respBad, err := dialer.Dial(wssURL, badHeader)
	if err == nil {
		t.Fatalf("expected dial with bad token to fail")
	}
	if respBad != nil && respBad.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", respBad.StatusCode)
	}

	// 3. Rate limiting test on the server AccessController
	for i := 0; i < 10; i++ {
		_, _, _ = dialer.Dial(wssURL, badHeader)
	}
	// 11th attempt from same IP should get 429 Too Many Requests
	_, respRate, err := dialer.Dial(wssURL, badHeader)
	if err == nil {
		t.Fatalf("expected dial to fail when rate limited")
	}
	if respRate != nil && respRate.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", respRate.StatusCode)
	}

	// 4. Reset rate limiter for the test IP and verify valid token connects cleanly
	srv.AccessController().RateLimiter().Reset("127.0.0.1")

	goodHeader := http.Header{}
	goodHeader.Set("Authorization", "Bearer cluster-secret-xyz")
	conn, respGood, err := dialer.Dial(wssURL, goodHeader)
	if err != nil {
		t.Fatalf("expected valid token dial to succeed, got: %v (resp: %+v)", err, respGood)
	}
	defer conn.Close()
}

func TestServerDevicesRESTAPI(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-server-devices-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	devicesPath := filepath.Join(tmpDir, "devices.json")
	srv, err := server.New(server.Config{
		Domain:           "fabric.test",
		Port:             8443,
		CADir:            caDir,
		Token:            "cluster-tok",
		AdminToken:       "admin-tok",
		WireGuardPort:    0,
		WireGuardDevices: devicesPath,
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	defer srv.Close()

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

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", serverPort)

	// 1. Initial list: should be empty
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer cluster-tok")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/devices failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK on GET /api/v1/devices, got %d", resp.StatusCode)
	}

	// 2. Register new device: POST /api/v1/devices
	clientPrivB64, clientPubB64, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatalf("wireguard.GenerateKeypair failed: %v", err)
	}
	_ = clientPrivB64
	postBody := strings.NewReader(fmt.Sprintf(`{"name":"ipad","public_key":"%s"}`, clientPubB64))
	reqPost, _ := http.NewRequest("POST", baseURL+"/api/v1/devices", postBody)
	reqPost.Header.Set("Authorization", "Bearer admin-tok")
	reqPost.Header.Set("Content-Type", "application/json")
	respPost, err := client.Do(reqPost)
	if err != nil {
		t.Fatalf("POST /api/v1/devices failed: %v", err)
	}
	defer respPost.Body.Close()
	if respPost.StatusCode != http.StatusOK {
		bodyB, _ := io.ReadAll(respPost.Body)
		t.Fatalf("expected 200 OK on POST /api/v1/devices, got %d: %s", respPost.StatusCode, string(bodyB))
	}

	var postResult map[string]interface{}
	json.NewDecoder(respPost.Body).Decode(&postResult)
	if postResult["name"] != "ipad" || postResult["virtual_ip"] != "100.64.128.1" {
		t.Errorf("unexpected post result: %+v", postResult)
	}

	// 3. Inspect device: GET /api/v1/devices/ipad
	reqGet, _ := http.NewRequest("GET", baseURL+"/api/v1/devices/ipad", nil)
	reqGet.Header.Set("Authorization", "Bearer cluster-tok")
	respGet, err := client.Do(reqGet)
	if err != nil {
		t.Fatalf("GET /api/v1/devices/ipad failed: %v", err)
	}
	defer respGet.Body.Close()
	if respGet.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK on GET /api/v1/devices/ipad, got %d", respGet.StatusCode)
	}

	// 4. Delete device: DELETE /api/v1/devices/ipad
	reqDel, _ := http.NewRequest("DELETE", baseURL+"/api/v1/devices/ipad", nil)
	reqDel.Header.Set("Authorization", "Bearer admin-tok")
	respDel, err := client.Do(reqDel)
	if err != nil {
		t.Fatalf("DELETE /api/v1/devices/ipad failed: %v", err)
	}
	defer respDel.Body.Close()
	if respDel.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK on DELETE /api/v1/devices/ipad, got %d", respDel.StatusCode)
	}
}

func TestServerDeviceEndpointsDisabledWireGuardErrorConformance(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-server-test-disabled-wg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")
	srv, err := server.New(server.Config{
		Domain:            "fabric.test",
		Port:              8443,
		CADir:             caDir,
		Token:             "cluster-tok",
		AdminToken:        "admin-tok",
		WireGuardDisabled: true,
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	defer srv.Close()

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
	tlsCfg, err := pki.BuildMTLSConfig(caCertPath)
	if err != nil {
		t.Fatalf("BuildMTLSConfig failed: %v", err)
	}

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", serverPort)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		Timeout: 5 * time.Second,
	}

	postBody := strings.NewReader(`{"name":"ipad","public_key":"dummy"}`)
	reqPost, _ := http.NewRequest("POST", baseURL+"/api/v1/devices", postBody)
	reqPost.Header.Set("Authorization", "Bearer admin-tok")
	reqPost.Header.Set("Content-Type", "application/json")
	respPost, err := client.Do(reqPost)
	if err != nil {
		t.Fatalf("POST /api/v1/devices failed: %v", err)
	}
	defer respPost.Body.Close()

	if respPost.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable, got %d", respPost.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(respPost.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))
	expectedError := "WireGuard engine is not enabled on this Server"
	if bodyStr != expectedError {
		t.Errorf("expected canonical error %q, got %q", expectedError, bodyStr)
	}
}




