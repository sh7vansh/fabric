package relay

import (
	"encoding/base64"
	"net"
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
		stream, err := cMux.Session.Accept()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 64)
		n, _ := stream.Read(buf)
		streamReceived <- string(buf[:n])
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
