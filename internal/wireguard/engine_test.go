package wireguard

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"fabric/internal/protocol"

	"github.com/miekg/dns"
)

type mockProxyRouter struct {
	routedHostname string
	routedEnvelope []byte
	routedStream   net.Conn
	handleFunc     func(targetHostname string, env []byte, stream net.Conn) error
}

func (m *mockProxyRouter) RouteProxyStream(targetHostname string, envelope []byte, srcStream net.Conn) error {
	m.routedHostname = targetHostname
	m.routedEnvelope = envelope
	m.routedStream = srcStream
	if m.handleFunc != nil {
		return m.handleFunc(targetHostname, envelope, srcStream)
	}
	return nil
}

func TestWireGuardEngineLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	devicesPath := filepath.Join(tempDir, "devices.json")
	keyPath := filepath.Join(tempDir, "server.key")

	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	store, err := NewDeviceStore(devicesPath)
	if err != nil {
		t.Fatalf("NewDeviceStore failed: %v", err)
	}

	router := &mockProxyRouter{}

	engine, err := NewEngine(EngineConfig{
		Port:        0,
		Subnet:      "100.64.0.0/10",
		KeyPath:     keyPath,
		DevicesPath: devicesPath,
		MeshDomain:  "fabric.mesh",
	}, ipam, store, router)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	if engine.ServerPublicKey() == "" {
		t.Errorf("expected non-empty server public key")
	}

	// Pair a client device
	clientPriv, clientPub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	dev, err := engine.AddDevice("iphone", clientPub)
	if err != nil {
		t.Fatalf("AddDevice failed: %v", err)
	}
	if dev.Name != "iphone" || dev.VirtualIP != "100.64.128.1" {
		t.Errorf("device unexpected fields: %+v", dev)
	}

	// Verify device in list
	devices := engine.ListDevices()
	if len(devices) != 1 || devices[0].Name != "iphone" {
		t.Errorf("expected 1 device, got %+v", devices)
	}

	// Remove device
	if err := engine.RemoveDevice("iphone"); err != nil {
		t.Fatalf("RemoveDevice failed: %v", err)
	}

	if len(engine.ListDevices()) != 0 {
		t.Errorf("expected 0 devices after removal")
	}

	_ = clientPriv
}

func TestInMemoryDNSResolution(t *testing.T) {
	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	threadIP, err := ipam.AllocateThreadIP("worker-1")
	if err != nil {
		t.Fatalf("AllocateThreadIP failed: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	mockPConn := newPipePacketConn(serverConn)

	dnsServer, err := NewDNSServer(mockPConn, ipam, "fabric.mesh")
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	defer dnsServer.Close()

	// Query worker-1.fabric.mesh.
	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("worker-1.fabric.mesh.", dns.TypeA)
	queryBytes, _ := queryMsg.Pack()

	go func() {
		_, _ = clientConn.Write(queryBytes)
	}()

	respBuf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read DNS response: %v", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBuf[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}

	if len(respMsg.Answer) == 0 {
		t.Fatalf("expected at least 1 answer, got 0")
	}

	aRec, ok := respMsg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A record, got %T", respMsg.Answer[0])
	}
	if !aRec.A.Equal(threadIP) {
		t.Errorf("expected IP %s, got %s", threadIP, aRec.A)
	}

	// Query server root: fabric.
	queryServer := new(dns.Msg)
	queryServer.SetQuestion("fabric.", dns.TypeA)
	qBytes, _ := queryServer.Pack()

	go func() {
		_, _ = clientConn.Write(qBytes)
	}()

	n, err = clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read server DNS response: %v", err)
	}
	respServer := new(dns.Msg)
	_ = respServer.Unpack(respBuf[:n])
	if len(respServer.Answer) == 0 {
		t.Fatalf("expected server root answer")
	}
	aServRec, _ := respServer.Answer[0].(*dns.A)
	if !aServRec.A.Equal(net.ParseIP("100.64.0.1")) {
		t.Errorf("expected server IP 100.64.0.1, got %s", aServRec.A)
	}
}

type pipePacketConn struct {
	net.Conn
}

func newPipePacketConn(c net.Conn) net.PacketConn {
	return &pipePacketConn{Conn: c}
}

func (p *pipePacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = p.Conn.Read(b)
	return n, p.Conn.RemoteAddr(), err
}

func (p *pipePacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return p.Conn.Write(b)
}

func TestTCPBridgeStreamForwarding(t *testing.T) {
	tempDir := t.TempDir()
	devicesPath := filepath.Join(tempDir, "devices.json")

	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	targetIP, err := ipam.AllocateThreadIP("backend-node")
	if err != nil {
		t.Fatalf("AllocateThreadIP failed: %v", err)
	}

	store, _ := NewDeviceStore(devicesPath)

	bridgedCh := make(chan string, 1)
	router := &mockProxyRouter{
		handleFunc: func(targetHostname string, env []byte, stream net.Conn) error {
			var req protocol.ProxyRequest
			if err := json.Unmarshal(env, &req); err != nil {
				t.Errorf("invalid envelope JSON: %v", err)
			}
			if req.TargetHostname != "backend-node" || req.TargetPort != 8080 {
				t.Errorf("unexpected ProxyRequest: %+v", req)
			}

			buf := make([]byte, 5)
			_, _ = io.ReadFull(stream, buf)
			bridgedCh <- string(buf)

			_, _ = stream.Write([]byte("WORLD"))
			return nil
		},
	}

	engine, err := NewEngine(EngineConfig{
		Port:        0,
		Subnet:      "100.64.0.0/10",
		DevicesPath: devicesPath,
	}, ipam, store, router)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	_ = engine.Bridge().ListenPort(8080)

	// Dial virtual TCP connection into target thread IP inside netstack
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	clientConn, err := engine.Netstack().DialContext(ctx, "tcp", net.JoinHostPort(targetIP.String(), "8080"))
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer clientConn.Close()

	// Write data across virtual tunnel
	_, err = clientConn.Write([]byte("HELLO"))
	if err != nil {
		t.Fatalf("clientConn.Write failed: %v", err)
	}

	select {
	case msg := <-bridgedCh:
		if msg != "HELLO" {
			t.Errorf("expected bridged msg 'HELLO', got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for bridged proxy stream")
	}

	// Read response from bridged daemon
	resp := make([]byte, 5)
	_, err = io.ReadFull(clientConn, resp)
	if err != nil {
		t.Fatalf("failed to read response from virtual client: %v", err)
	}
	if string(resp) != "WORLD" {
		t.Errorf("expected 'WORLD', got %q", string(resp))
	}
}
