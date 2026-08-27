package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/server"
	"fabric/internal/wireguard"

	"github.com/miekg/dns"
)

func TestWireGuardE2EFullStack(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")
	devicesPath := filepath.Join(tmpDir, "devices.json")

	// 1. Initialize Server with embedded WireGuard Gateway
	srv, err := server.New(server.Config{
		Domain:           "fabric.mesh",
		Port:             8443,
		CADir:            caDir,
		Token:            "cluster-secret-key",
		AdminToken:       "admin-secret-key",
		WireGuardPort:    0, // Ephemeral UDP port
		WireGuardDevices: devicesPath,
		WireGuardSubnet:  "100.64.0.0/10",
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	defer srv.Close()

	// Spin up server TLS listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
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

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		Timeout: 5 * time.Second,
	}

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", serverPort)

	// 2. Register a Thread on the Server
	nodeMeta := protocol.NodeMetadata{
		ID:       "worker-gpu-1",
		Hostname: "worker-gpu-1",
		OS:       "linux",
		Arch:     "amd64",
		Domain:   "fabric.mesh",
	}
	if _, err := srv.Relay().RegisterNode(nodeMeta, nil); err != nil {
		t.Fatalf("RegisterNode failed: %v", err)
	}

	// Verify IPAM allocated thread IP
	threadIP, ok := srv.IPAM().LookupIPByHostname("worker-gpu-1")
	if !ok || threadIP == nil {
		t.Fatalf("thread IP was not registered in IPAM")
	}
	if threadIP.String() != "100.64.0.2" {
		t.Errorf("expected thread IP 100.64.0.2, got %s", threadIP)
	}

	// 3. Pair a client Device via REST API: POST /api/v1/devices
	clientPriv, clientPub, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatalf("wireguard.GenerateKeypair failed: %v", err)
	}
	_ = clientPriv

	postBody := bytes.NewBufferString(fmt.Sprintf(`{"name":"macbook-air","public_key":"%s"}`, clientPub))
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/devices", postBody)
	req.Header.Set("Authorization", "Bearer admin-secret-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/devices failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyB, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /api/v1/devices returned %d: %s", resp.StatusCode, string(bodyB))
	}

	var reg wireguard.DeviceEntry
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	if reg.Name != "macbook-air" || reg.VirtualIP != "100.64.128.1" {
		t.Errorf("unexpected device registration: %+v", reg)
	}

	// 4. Test In-Memory DNS server attached to netstack
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	mockPConn := newMockPacketConn(serverConn)
	dnsServer, err := wireguard.NewDNSServer(mockPConn, srv.IPAM(), "fabric.mesh")
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	defer dnsServer.Close()

	// Query worker-gpu-1.fabric.mesh.
	qMsg := new(dns.Msg)
	qMsg.SetQuestion("worker-gpu-1.fabric.mesh.", dns.TypeA)
	qBytes, _ := qMsg.Pack()

	go func() {
		_, _ = clientConn.Write(qBytes)
	}()

	dnsBuf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(dnsBuf)
	if err != nil {
		t.Fatalf("failed to read DNS reply: %v", err)
	}

	rMsg := new(dns.Msg)
	_ = rMsg.Unpack(dnsBuf[:n])
	if len(rMsg.Answer) == 0 {
		t.Fatalf("expected DNS answer for worker-gpu-1.fabric.mesh, got 0")
	}
	aRec := rMsg.Answer[0].(*dns.A)
	if !aRec.A.Equal(threadIP) {
		t.Errorf("DNS resolved to %s, expected %s", aRec.A, threadIP)
	}

	// 5. Test Listing Devices: GET /api/v1/devices
	reqList, _ := http.NewRequest("GET", baseURL+"/api/v1/devices", nil)
	reqList.Header.Set("Authorization", "Bearer cluster-secret-key")
	respList, err := httpClient.Do(reqList)
	if err != nil {
		t.Fatalf("GET /api/v1/devices failed: %v", err)
	}
	defer respList.Body.Close()
	var devList []wireguard.DeviceEntry
	_ = json.NewDecoder(respList.Body).Decode(&devList)
	if len(devList) != 1 || devList[0].Name != "macbook-air" {
		t.Errorf("expected 1 device 'macbook-air', got %+v", devList)
	}

	// 6. Test Revoking Device: DELETE /api/v1/devices/macbook-air
	reqDel, _ := http.NewRequest("DELETE", baseURL+"/api/v1/devices/macbook-air", nil)
	reqDel.Header.Set("Authorization", "Bearer admin-secret-key")
	respDel, err := httpClient.Do(reqDel)
	if err != nil {
		t.Fatalf("DELETE /api/v1/devices/macbook-air failed: %v", err)
	}
	defer respDel.Body.Close()
	if respDel.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK on DELETE, got %d", respDel.StatusCode)
	}

	// 7. Verify device store and IPAM reclaimed the IP
	if _, found := srv.WireGuardEngine().Store().Get("macbook-air"); found {
		t.Errorf("device should have been removed from store")
	}
	if _, found := srv.IPAM().LookupDeviceByName("macbook-air"); found {
		t.Errorf("device IP should have been released from IPAM")
	}
}

type mockPacketConn struct {
	net.Conn
}

func newMockPacketConn(c net.Conn) net.PacketConn {
	return &mockPacketConn{Conn: c}
}

func (m *mockPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = m.Conn.Read(b)
	return n, m.Conn.RemoteAddr(), err
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return m.Conn.Write(b)
}
