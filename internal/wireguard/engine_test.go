package wireguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
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

func TestEngineThreadSubnetFullRangeAcceptance(t *testing.T) {
	tempDir := t.TempDir()
	devicesPath := filepath.Join(tempDir, "devices.json")

	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	// Specifically test Thread IPs with octet3 > 15 (e.g. 100.64.16.1, 100.64.64.1, 100.64.127.254)
	testIPs := []string{"100.64.16.1", "100.64.64.1", "100.64.127.254"}
	for i, ipStr := range testIPs {
		hostname := fmt.Sprintf("worker-high-%d", i)
		parsedIP := net.ParseIP(ipStr)
		if err := ipam.ReserveThreadIP(hostname, parsedIP); err != nil {
			t.Fatalf("ReserveThreadIP failed for %s: %v", ipStr, err)
		}
	}

	store, _ := NewDeviceStore(devicesPath)
	router := &mockProxyRouter{
		handleFunc: func(targetHostname string, env []byte, stream net.Conn) error {
			_, _ = stream.Write([]byte("OK"))
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

	for _, ipStr := range testIPs {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		clientConn, err := engine.Netstack().DialContext(ctx, "tcp", net.JoinHostPort(ipStr, "8080"))
		if err != nil {
			cancel()
			t.Fatalf("DialContext failed for thread IP %s in full range: %v", ipStr, err)
		}
		buf := make([]byte, 2)
		_, _ = io.ReadFull(clientConn, buf)
		_ = clientConn.Close()
		cancel()
		if string(buf) != "OK" {
			t.Errorf("for IP %s, expected 'OK', got %q", ipStr, string(buf))
		}
	}
}

func TestDNSRecursiveUpstreamForwarding(t *testing.T) {
	// 1. Start mock upstream public DNS resolver
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock upstream DNS listener: %v", err)
	}
	defer upstreamConn.Close()

	upstreamAddr := upstreamConn.LocalAddr().String()

	upstreamMux := dns.NewServeMux()
	upstreamMux.HandleFunc("public-service.example.org.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("93.184.216.34").To4(),
		})
		_ = w.WriteMsg(m)
	})

	upstreamServer := &dns.Server{
		PacketConn: upstreamConn,
		Handler:    upstreamMux,
	}
	go func() {
		_ = upstreamServer.ActivateAndServe()
	}()
	defer upstreamServer.Shutdown()

	// 2. Initialize Fabric DNS Server configured with upstream resolver
	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	mockPConn := newPipePacketConn(serverConn)

	dnsServer, err := NewDNSServerWithUpstream(mockPConn, ipam, "fabric.mesh", upstreamAddr)
	if err != nil {
		t.Fatalf("NewDNSServerWithUpstream failed: %v", err)
	}
	defer dnsServer.Close()

	// 3. Query public-service.example.org. via tunnel DNS
	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("public-service.example.org.", dns.TypeA)
	queryBytes, _ := queryMsg.Pack()

	go func() {
		_, _ = clientConn.Write(queryBytes)
	}()

	respBuf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read recursive DNS response: %v", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBuf[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}

	if len(respMsg.Answer) == 0 {
		t.Fatalf("expected recursive DNS answer for public domain, got 0 answers (Rcode: %d)", respMsg.Rcode)
	}

	aRec, ok := respMsg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A record, got %T", respMsg.Answer[0])
	}
	if !aRec.A.Equal(net.ParseIP("93.184.216.34")) {
		t.Errorf("expected IP 93.184.216.34, got %s", aRec.A)
	}
}

func TestTCPBridgeDynamicCustomPorts(t *testing.T) {
	tempDir := t.TempDir()
	devicesPath := filepath.Join(tempDir, "devices.json")

	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	targetIP, err := ipam.AllocateThreadIP("custom-port-worker")
	if err != nil {
		t.Fatalf("AllocateThreadIP failed: %v", err)
	}

	store, _ := NewDeviceStore(devicesPath)
	routedPorts := make(map[int]bool)
	var mu sync.Mutex

	router := &mockProxyRouter{
		handleFunc: func(targetHostname string, env []byte, stream net.Conn) error {
			var req protocol.ProxyRequest
			_ = json.Unmarshal(env, &req)
			mu.Lock()
			routedPorts[req.TargetPort] = true
			mu.Unlock()
			_, _ = stream.Write([]byte("PONG"))
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

	// Listen on individual custom port, variadic ports, and port range
	if err := engine.Bridge().ListenPort(3128); err != nil {
		t.Fatalf("ListenPort failed: %v", err)
	}
	if err := engine.Bridge().ListenPorts(8888, 9200); err != nil {
		t.Fatalf("ListenPorts failed: %v", err)
	}
	if err := engine.Bridge().ListenRange(7000, 7002); err != nil {
		t.Fatalf("ListenRange failed: %v", err)
	}

	testPorts := []int{3128, 8888, 9200, 7000, 7001, 7002}
	for _, port := range testPorts {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		clientConn, err := engine.Netstack().DialContext(ctx, "tcp", net.JoinHostPort(targetIP.String(), fmt.Sprintf("%d", port)))
		if err != nil {
			cancel()
			t.Fatalf("DialContext failed for custom port %d: %v", port, err)
		}
		buf := make([]byte, 4)
		_, _ = io.ReadFull(clientConn, buf)
		_ = clientConn.Close()
		cancel()

		if string(buf) != "PONG" {
			t.Errorf("for port %d expected 'PONG', got %q", port, string(buf))
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, port := range testPorts {
		if !routedPorts[port] {
			t.Errorf("expected port %d to be recorded in router, got routedPorts: %+v", port, routedPorts)
		}
	}
}

func TestEngineDeviceSubnetFullRangeAcceptance(t *testing.T) {
	tempDir := t.TempDir()
	devicesPath := filepath.Join(tempDir, "devices.json")

	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
	}

	testDeviceIPs := []string{"100.64.128.1", "100.64.200.10", "100.64.255.254"}
	for i, ipStr := range testDeviceIPs {
		devName := fmt.Sprintf("device-range-%d", i)
		parsedIP := net.ParseIP(ipStr)
		if err := ipam.ReserveDeviceIP(devName, parsedIP); err != nil {
			t.Fatalf("ReserveDeviceIP failed for %s: %v", ipStr, err)
		}
	}

	store, _ := NewDeviceStore(devicesPath)
	router := &mockProxyRouter{
		handleFunc: func(targetHostname string, env []byte, stream net.Conn) error {
			_, _ = stream.Write([]byte("DEV_OK"))
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

	for _, ipStr := range testDeviceIPs {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		clientConn, err := engine.Netstack().DialContext(ctx, "tcp", net.JoinHostPort(ipStr, "8080"))
		if err != nil {
			cancel()
			t.Fatalf("DialContext failed for device IP %s in overlay range: %v", ipStr, err)
		}
		buf := make([]byte, 6)
		_, _ = io.ReadFull(clientConn, buf)
		_ = clientConn.Close()
		cancel()
		if string(buf) != "DEV_OK" {
			t.Errorf("for device IP %s, expected 'DEV_OK', got %q", ipStr, string(buf))
		}
	}
}

func TestDNSCanonicalServerDomainResolution(t *testing.T) {
	ipam, err := NewIPAMManager("100.64.0.0/10")
	if err != nil {
		t.Fatalf("NewIPAMManager failed: %v", err)
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

	// 1. Canonical query: server.fabric.
	qMsg := new(dns.Msg)
	qMsg.SetQuestion("server.fabric.", dns.TypeA)
	qBytes, _ := qMsg.Pack()

	go func() { _, _ = clientConn.Write(qBytes) }()
	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read DNS response: %v", err)
	}
	resp := new(dns.Msg)
	_ = resp.Unpack(buf[:n])
	if len(resp.Answer) == 0 {
		t.Fatalf("expected server.fabric. to resolve to Server IP")
	}
	if aRec, ok := resp.Answer[0].(*dns.A); !ok || !aRec.A.Equal(net.ParseIP("100.64.0.1")) {
		t.Errorf("expected 100.64.0.1 for server.fabric., got %v", resp.Answer[0])
	}

	// 2. Non-canonical query: gateway.fabric. should NOT be treated as server root
	qMsgLegacy := new(dns.Msg)
	qMsgLegacy.SetQuestion("gateway.fabric.", dns.TypeA)
	qBytesLegacy, _ := qMsgLegacy.Pack()

	go func() { _, _ = clientConn.Write(qBytesLegacy) }()
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read DNS response for legacy gateway: %v", err)
	}
	respLegacy := new(dns.Msg)
	_ = respLegacy.Unpack(buf[:n])
	if respLegacy.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN for non-canonical gateway.fabric. query, got Rcode %d", respLegacy.Rcode)
	}
}





