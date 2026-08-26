package relay

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"fabric/internal/protocol"

	"github.com/hashicorp/yamux"
	"github.com/miekg/dns"
)

func createMockMultiplexers(t *testing.T) (*protocol.StreamMultiplexer, *protocol.StreamMultiplexer) {
	p1, p2 := net.Pipe()

	serverSession, err := yamux.Server(p1, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux.Server failed: %v", err)
	}

	clientSession, err := yamux.Client(p2, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux.Client failed: %v", err)
	}

	return &protocol.StreamMultiplexer{Session: serverSession}, &protocol.StreamMultiplexer{Session: clientSession}
}

func TestRelayNodeRegistrationAndDisplacement(t *testing.T) {
	r := New(Config{
		Domain:   "fabric.mesh",
		Token:    "secret-123",
		PingFreq: 0,
	})
	defer r.Close()

	if !r.ValidateToken("secret-123") {
		t.Errorf("expected token validation to pass")
	}
	if r.ValidateToken("wrong") {
		t.Errorf("expected token validation to fail for wrong token")
	}

	sMux1, cMux1 := createMockMultiplexers(t)
	defer cMux1.Session.Close()

	meta1 := protocol.NodeMetadata{
		Hostname: "worker-1",
		OS:       "linux",
		Arch:     "amd64",
		Tags:     []string{"web", "prod"},
	}

	sess1, err := r.RegisterNode(meta1, sMux1)
	if err != nil {
		t.Fatalf("RegisterNode failed: %v", err)
	}
	if sess1.Metadata.Hostname != "worker-1" {
		t.Errorf("unexpected hostname: %s", sess1.Metadata.Hostname)
	}
	if len(sess1.Metadata.Tags) != 2 || sess1.Metadata.Tags[0] != "web" {
		t.Errorf("unexpected tags: %v", sess1.Metadata.Tags)
	}

	// Verify GetNode and ListNodes
	got, ok := r.GetNode("worker-1")
	if !ok || got.Hostname != "worker-1" {
		t.Errorf("GetNode failed to find worker-1")
	}
	if len(got.Tags) != 2 || got.Tags[1] != "prod" {
		t.Errorf("GetNode tags mismatch: %v", got.Tags)
	}
	if len(r.ListNodes()) != 1 {
		t.Errorf("expected 1 node in list, got %d", len(r.ListNodes()))
	}

	// Displacement: connect same hostname with new mux without tags -> preserves tags
	sMux2, cMux2 := createMockMultiplexers(t)
	defer cMux2.Session.Close()

	meta2 := protocol.NodeMetadata{
		Hostname: "worker-1",
		OS:       "linux",
		Arch:     "arm64",
	}

	sess2, err := r.RegisterNode(meta2, sMux2)
	if err != nil {
		t.Fatalf("second RegisterNode failed: %v", err)
	}
	if sess2.Metadata.Arch != "arm64" {
		t.Errorf("expected updated arch arm64, got %s", sess2.Metadata.Arch)
	}
	if len(sess2.Metadata.Tags) != 2 || sess2.Metadata.Tags[0] != "web" {
		t.Errorf("expected preserved tags across displacement, got %v", sess2.Metadata.Tags)
	}

	time.Sleep(50 * time.Millisecond)
	if !sMux1.Session.IsClosed() {
		t.Errorf("expected displaced session 1 to be closed")
	}

	// Disconnecting session 2 unregisters node
	sMux2.Session.Close()
	time.Sleep(50 * time.Millisecond)

	if _, ok := r.GetNode("worker-1"); ok {
		t.Errorf("expected worker-1 to be unregistered after session closure")
	}
}

func TestRelayResolveDNS(t *testing.T) {
	r := New(Config{
		Domain:   "fabric.mesh",
		Token:    "secret",
		PingFreq: 0,
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()

	r.RegisterNode(protocol.NodeMetadata{Hostname: "api"}, sMux)

	proxyIP := "10.42.0.1"

	// 1. Existing node A query
	m := new(dns.Msg)
	m.SetQuestion("api.fabric.mesh.", dns.TypeA)
	wire, _ := m.Pack()

	q := protocol.DNSQuery{
		Type:      protocol.TypeDNSQuery,
		SessionID: "sess-1",
		Data:      base64.StdEncoding.EncodeToString(wire),
	}

	resp := r.ResolveDNS(q, proxyIP)
	if resp.RCode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", resp.RCode)
	}
	if resp.TTL != 10 {
		t.Errorf("expected TTL 10, got %d", resp.TTL)
	}

	respWire, _ := base64.StdEncoding.DecodeString(resp.Data)
	mResp := new(dns.Msg)
	if err := mResp.Unpack(respWire); err != nil {
		t.Fatalf("failed to unpack DNS reply: %v", err)
	}
	if len(mResp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(mResp.Answer))
	}
	aRecord, ok := mResp.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != proxyIP {
		t.Errorf("expected A record with IP %s, got %v", proxyIP, mResp.Answer[0])
	}

	// 2. Subdomain wildcard on existing node (e.g. sub.api.fabric.mesh)
	mWild := new(dns.Msg)
	mWild.SetQuestion("sub.api.fabric.mesh.", dns.TypeA)
	wildWire, _ := mWild.Pack()
	respWild := r.ResolveDNS(protocol.DNSQuery{
		Data: base64.StdEncoding.EncodeToString(wildWire),
	}, proxyIP)
	if respWild.RCode != dns.RcodeSuccess {
		t.Errorf("expected subdomain wildcard to resolve, got %d", respWild.RCode)
	}

	// 3. Non-existent node -> NXDOMAIN
	mMissing := new(dns.Msg)
	mMissing.SetQuestion("unknown.fabric.mesh.", dns.TypeA)
	missingWire, _ := mMissing.Pack()
	respMissing := r.ResolveDNS(protocol.DNSQuery{
		Data: base64.StdEncoding.EncodeToString(missingWire),
	}, proxyIP)
	if respMissing.RCode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN (RcodeNameError), got %d", respMissing.RCode)
	}
	if respMissing.TTL != 5 {
		t.Errorf("expected negative TTL 5, got %d", respMissing.TTL)
	}
}

func TestRelayRouteStream(t *testing.T) {
	r := New(Config{
		Domain:   "fabric.mesh",
		Token:    "secret",
		PingFreq: 0,
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()

	r.RegisterNode(protocol.NodeMetadata{Hostname: "target-node"}, sMux)

	// Stream handler on client side (target-node agent)
	streamReceived := make(chan string, 1)
	go func() {
		for {
			stream, err := cMux.Session.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			n, _ := stream.Read(buf)
			content := string(buf[:n])
			if strings.Contains(content, "node_sync") {
				stream.Close()
				continue
			}
			streamReceived <- content
			stream.Close()
			return
		}
	}()

	srcConn, cliConn := net.Pipe()
	defer cliConn.Close()

	err := r.RouteStream("target-node", []byte("hello-envelope"), srcConn)
	if err != nil {
		t.Fatalf("RouteStream failed: %v", err)
	}

	select {
	case env := <-streamReceived:
		if env != "hello-envelope" {
			t.Errorf("expected 'hello-envelope', got %q", env)
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("timed out waiting for routed stream")
	}
}

func TestRelayServeMuxEndToEnd(t *testing.T) {
	r := New(Config{
		Domain:   "fabric.mesh",
		Token:    "cluster-token",
		PingFreq: 0,
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()

	// Run ServeMux in background
	go func() {
		_ = r.ServeMux(sMux, "192.168.1.100:54321", "10.0.0.1")
	}()

	// 1. Send Handshake from node agent side
	handshakeStream, err := cMux.Session.Open()
	if err != nil {
		t.Fatalf("failed to open handshake stream: %v", err)
	}

	hsPayload := `{"type":"handshake","hostname":"node-alpha","token":"cluster-token","domain":"fabric.mesh","os":"linux","arch":"amd64","tags":["worker"]}`
	_, _ = handshakeStream.Write([]byte(hsPayload))
	handshakeStream.Close()

	time.Sleep(50 * time.Millisecond)

	// Verify node registered automatically
	node, ok := r.GetNode("node-alpha")
	if !ok {
		t.Fatalf("expected node-alpha to be registered via ServeMux handshake")
	}
	if node.RemoteIP != "192.168.1.100:54321" {
		t.Errorf("expected remote IP 192.168.1.100:54321, got: %s", node.RemoteIP)
	}
	if len(node.Tags) != 1 || node.Tags[0] != "worker" {
		t.Errorf("expected tag 'worker', got: %v", node.Tags)
	}

	// 2. Query DNS via ServeMux router
	dnsStream, err := cMux.Session.Open()
	if err != nil {
		t.Fatalf("failed to open dns stream: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion("node-alpha.fabric.mesh.", dns.TypeA)
	wire, _ := m.Pack()

	dnsQueryPayload := `{"type":"dns_query","sessionId":"test-dns-1","data":"` + base64.StdEncoding.EncodeToString(wire) + `"}`
	_, _ = dnsStream.Write([]byte(dnsQueryPayload))
	dnsStream.Close()

	// Wait for DNS response stream opened by Relay
	respStream, err := cMux.Session.Accept()
	if err != nil {
		t.Fatalf("failed to accept dns response stream: %v", err)
	}
	defer respStream.Close()

	buf := make([]byte, 2048)
	n, _ := respStream.Read(buf)
	if n == 0 {
		t.Fatalf("expected non-empty DNS response")
	}
}

func TestRelayServeMuxUnauthorized(t *testing.T) {
	r := New(Config{
		Domain:   "fabric.mesh",
		Token:    "correct-secret",
		PingFreq: 0,
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)

	go func() {
		_ = r.ServeMux(sMux, "10.0.0.2:12345", "10.0.0.1")
	}()

	stream, err := cMux.Session.Open()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	// Send wrong token
	_, _ = stream.Write([]byte(`{"type":"handshake","hostname":"bad-node","token":"wrong-secret"}`))
	stream.Close()

	time.Sleep(50 * time.Millisecond)

	// Node should NOT be registered
	if _, ok := r.GetNode("bad-node"); ok {
		t.Errorf("unauthorized node should not be registered")
	}

	// Session should be closed
	if !sMux.Session.IsClosed() {
		t.Errorf("expected unauthorized session to be closed")
	}
}

func TestRelayHostnameValidation(t *testing.T) {
	r := New(Config{
		Domain: "fabric.mesh",
		Token:  "test-token",
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()

	invalidNames := []string{
		"node\npoison",
		"node\r\npoison",
		"node 1",
		"-invalid-start",
		"invalid-end-",
		"invalid_underscore",
		"very-long-hostname-that-exceeds-the-maximum-sixty-three-character-limit-allowed-by-rfc-1123",
		"",
	}

	for _, name := range invalidNames {
		_, err := r.RegisterNode(protocol.NodeMetadata{
			Hostname: name,
		}, sMux)
		if err == nil {
			t.Errorf("RegisterNode(%q) expected error for invalid RFC 1123 hostname, got nil", name)
		}
	}

	validNames := []string{
		"node-1",
		"web",
		"db-prod-01",
		"a",
		"123",
	}

	for _, name := range validNames {
		sess, err := r.RegisterNode(protocol.NodeMetadata{
			Hostname: name,
		}, sMux)
		if err != nil {
			t.Errorf("RegisterNode(%q) unexpected error for valid RFC 1123 hostname: %v", name, err)
		}
		if sess == nil || sess.Metadata.Hostname != name {
			t.Errorf("RegisterNode(%q) returned invalid session: %+v", name, sess)
		}
	}
}

func TestRelayPingLoopConcurrentTelemetryReadWrite(t *testing.T) {
	r := New(Config{
		Domain:   "fabric.mesh",
		Token:    "test-token",
		PingFreq: 5 * time.Millisecond,
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()

	_, err := r.RegisterNode(protocol.NodeMetadata{
		Hostname: "worker-telemetry",
	}, sMux)
	if err != nil {
		t.Fatalf("RegisterNode failed: %v", err)
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Spin up concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					nodes := r.ListNodes()
					if len(nodes) > 0 {
						_ = nodes[0].LastSeen
					}
					if node, ok := r.GetNode("worker-telemetry"); ok {
						_ = node.LastSeen
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}

func TestRelayAdminTokenRoleSeparation(t *testing.T) {
	r := New(Config{
		Domain:     "fabric.mesh",
		Token:      "worker-token-xyz",
		AdminToken: "admin-secret-999",
	})
	defer r.Close()

	// 1. Worker token validates under general ValidateToken
	if !r.ValidateToken("worker-token-xyz") {
		t.Errorf("expected worker token to pass ValidateToken")
	}

	// 2. Admin token also validates under general ValidateToken
	if !r.ValidateToken("admin-secret-999") {
		t.Errorf("expected admin token to pass ValidateToken")
	}

	// 3. Worker token FAILS ValidateAdminToken
	if r.ValidateAdminToken("worker-token-xyz") {
		t.Errorf("worker token should NOT pass ValidateAdminToken")
	}

	// 4. Admin token PASSES ValidateAdminToken
	if !r.ValidateAdminToken("admin-secret-999") {
		t.Errorf("admin token must pass ValidateAdminToken")
	}

	// 5. Random token fails both
	if r.ValidateToken("unauthorized") || r.ValidateAdminToken("unauthorized") {
		t.Errorf("unauthorized token must fail both validations")
	}
}

func TestRelayAdminTokenUnsetRejection(t *testing.T) {
	r := New(Config{
		Domain: "fabric.mesh",
		Token:  "worker-token-only",
	})
	defer r.Close()

	if !r.ValidateToken("worker-token-only") {
		t.Errorf("expected worker token to pass ValidateToken")
	}

	// When AdminToken is unset, worker token must NOT be treated as admin token
	if r.ValidateAdminToken("worker-token-only") {
		t.Errorf("worker token should NOT pass ValidateAdminToken when AdminToken is unset")
	}
	if r.ValidateAdminToken("") {
		t.Errorf("empty token should NOT pass ValidateAdminToken")
	}
}

func TestRelayHandshakeProtocolVersionRejection(t *testing.T) {
	r := New(Config{
		Domain: "fabric.mesh",
		Token:  "test-token",
	})
	defer r.Close()

	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()

	go r.ServeMux(sMux, "127.0.0.1:12345", "127.0.0.1")

	// Send handshake with incompatible major protocol version (e.g. "99.0.0")
	stream, err := cMux.Session.Open()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	hs := protocol.Handshake{
		Type:            protocol.TypeHandshake,
		Hostname:        "incompatible-node",
		Token:           "test-token",
		ProtocolVersion: "99.0.0",
	}
	b, _ := json.Marshal(hs)
	_, _ = stream.Write(b)
	_ = stream.Close()

	// Wait briefly for relay to process and close session
	time.Sleep(50 * time.Millisecond)

	// Node should NOT be registered
	if _, ok := r.GetNode("incompatible-node"); ok {
		t.Errorf("incompatible protocol version node should NOT be registered")
	}
}

