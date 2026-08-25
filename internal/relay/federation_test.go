package relay

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"

	"github.com/miekg/dns"
)

func TestGatewayPeeringHandshakeAndDeduplication(t *testing.T) {
	serverA := New(Config{
		Domain:    "us-east.fabric",
		Token:     "secret-token",
		GatewayID: "gw-us-east",
		Region:    "us-east",
	})
	defer serverA.Close()

	serverB := New(Config{
		Domain:    "eu-west.fabric",
		Token:     "secret-token",
		GatewayID: "gw-eu-west",
		Region:    "eu-west",
	})
	defer serverB.Close()

	if serverA.GatewayID() != "gw-us-east" {
		t.Errorf("expected gateway ID gw-us-east, got %s", serverA.GatewayID())
	}
	if serverB.GatewayID() != "gw-eu-west" {
		t.Errorf("expected gateway ID gw-eu-west, got %s", serverB.GatewayID())
	}

	// 1. Establish mock Yamux peering session
	sMuxB, cMuxA := createMockMultiplexers(t)
	defer sMuxB.Session.Close()
	defer cMuxA.Session.Close()

	// Server B accepts peer connections via ServePeerMux
	go func() {
		_ = serverB.ServePeerMux(sMuxB, "10.0.0.1:443", false, "")
	}()

	// Server A initiates handshake to Server B
	stream, err := cMuxA.Session.Open()
	if err != nil {
		t.Fatalf("Server A failed to open stream: %v", err)
	}

	helloA := protocol.GatewayHello{
		Type:         protocol.TypeGatewayHello,
		GatewayID:    "gw-us-east",
		Domain:       "us-east.fabric",
		Region:       "us-east",
		Capabilities: []string{"exec", "cp", "proxy", "dns"},
		Token:        "secret-token",
		IsLeaf:       false,
	}
	b, _ := json.Marshal(helloA)
	_, _ = stream.Write(b)

	// Server A reads Server B's hello reply
	var helloB protocol.GatewayHello
	decoder := json.NewDecoder(stream)
	if err := decoder.Decode(&helloB); err != nil {
		t.Fatalf("failed to decode Server B hello reply: %v", err)
	}
	stream.Close()

	if helloB.GatewayID != "gw-eu-west" {
		t.Errorf("expected Server B gateway ID gw-eu-west, got %s", helloB.GatewayID)
	}

	time.Sleep(50 * time.Millisecond)

	// Server B should now have Server A in its peers list
	peersB := serverB.ListPeers()
	if len(peersB) != 1 {
		t.Fatalf("expected Server B to have 1 peer, got %d", len(peersB))
	}
	if peersB[0].GatewayID != "gw-us-east" || peersB[0].Region != "us-east" {
		t.Errorf("unexpected peer info on Server B: %+v", peersB[0])
	}
	if peersB[0].Topology != "core" {
		t.Errorf("expected core topology, got %s", peersB[0].Topology)
	}

	// 2. Test Deduplication tie-breaker: Server A (gw-us-east) > Server B (gw-eu-west) lexicographically
	sMuxB2, cMuxA2 := createMockMultiplexers(t)
	defer sMuxB2.Session.Close()
	defer cMuxA2.Session.Close()

	go func() {
		_ = serverB.ServePeerMux(sMuxB2, "10.0.0.1:443", false, "")
	}()

	stream2, err := cMuxA2.Session.Open()
	if err != nil {
		t.Fatalf("failed to open duplicate stream: %v", err)
	}
	_, _ = stream2.Write(b)
	stream2.Close()

	time.Sleep(50 * time.Millisecond)

	// Server B should still only have 1 peer after deduplication
	peersBAfter := serverB.ListPeers()
	if len(peersBAfter) != 1 {
		t.Fatalf("expected Server B to still have 1 peer after deduplication, got %d", len(peersBAfter))
	}
}

func TestFederatedThreadAdvertisementAndWithdrawal(t *testing.T) {
	serverA := New(Config{
		Domain:    "us-east.fabric",
		GatewayID: "gw-us-east",
	})
	defer serverA.Close()

	serverB := New(Config{
		Domain:    "eu-west.fabric",
		GatewayID: "gw-eu-west",
	})
	defer serverB.Close()

	sMuxB, cMuxA := createMockMultiplexers(t)
	defer sMuxB.Session.Close()
	defer cMuxA.Session.Close()

	// Register peer session directly on serverA and serverB
	peerOnA := &GatewayPeerSession{
		GatewayID: "gw-eu-west",
		Domain:    "eu-west.fabric",
		Region:    "eu-west",
		Topology:  "core",
		Mux:       cMuxA,
	}
	serverA.RegisterPeer(peerOnA)

	peerOnB := &GatewayPeerSession{
		GatewayID: "gw-us-east",
		Domain:    "us-east.fabric",
		Region:    "us-east",
		Topology:  "core",
		Mux:       sMuxB,
	}
	serverB.RegisterPeer(peerOnB)

	// Serve router on Server A and Server B to receive advertisements
	go func() { _ = serverA.ServePeerMux(cMuxA, "", false, "gw-eu-west") }()
	go func() { _ = serverB.ServePeerMux(sMuxB, "", false, "gw-us-east") }()

	// Connect a local agent "worker-1" to Server B
	agentMuxS, agentMuxC := createMockMultiplexers(t)
	defer agentMuxC.Session.Close()

	_, err := serverB.RegisterNode(protocol.NodeMetadata{
		Hostname: "worker-1",
		OS:       "linux",
		Arch:     "amd64",
		Tags:     []string{"backend"},
	}, agentMuxS)
	if err != nil {
		t.Fatalf("failed to register node on Server B: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Server A should now see worker-1 in its ListNodes() with GatewayID="gw-eu-west"
	nodesOnA := serverA.ListNodes()
	found := false
	for _, n := range nodesOnA {
		if n.Hostname == "worker-1" {
			found = true
			if n.GatewayID != "gw-eu-west" {
				t.Errorf("expected GatewayID gw-eu-west on Server A, got %s", n.GatewayID)
			}
		}
	}
	if !found {
		t.Fatalf("worker-1 was not advertised to Server A: %+v", nodesOnA)
	}

	// Now unregister worker-1 from Server B -> withdraw should propagate to Server A
	serverB.UnregisterNode("worker-1")
	time.Sleep(100 * time.Millisecond)

	nodesOnAAfter := serverA.ListNodes()
	for _, n := range nodesOnAAfter {
		if n.Hostname == "worker-1" {
			t.Errorf("expected worker-1 to be withdrawn from Server A, but still found")
		}
	}
}

func TestCrossGatewayExecRoutingAndLoopAvoidance(t *testing.T) {
	serverA := New(Config{
		Domain:    "us-east.fabric",
		GatewayID: "gw-us-east",
	})
	defer serverA.Close()

	serverB := New(Config{
		Domain:    "eu-west.fabric",
		GatewayID: "gw-eu-west",
	})
	defer serverB.Close()

	sMuxB, cMuxA := createMockMultiplexers(t)
	defer sMuxB.Session.Close()
	defer cMuxA.Session.Close()

	peerOnA := &GatewayPeerSession{
		GatewayID: "gw-eu-west",
		Mux:       cMuxA,
	}
	serverA.RegisterPeer(peerOnA)

	peerOnB := &GatewayPeerSession{
		GatewayID: "gw-us-east",
		Mux:       sMuxB,
	}
	serverB.RegisterPeer(peerOnB)

	go func() { _ = serverB.ServePeerMux(sMuxB, "", false, "gw-us-east") }()

	// Connect agent on Server B
	agentMuxS, agentMuxC := createMockMultiplexers(t)
	defer agentMuxC.Session.Close()

	serverB.RegisterNode(protocol.NodeMetadata{
		Hostname:  "db-eu",
		GatewayID: "gw-eu-west",
	}, agentMuxS)

	// Simulate Agent on Server B receiving routed stream
	agentReceived := make(chan string, 1)
	go func() {
		for {
			st, err := agentMuxC.Session.Accept()
			if err != nil {
				return
			}
			var req protocol.ExecRequest
			dec := json.NewDecoder(st)
			if err := dec.Decode(&req); err == nil && req.Type == protocol.TypeExecRequest {
				buf := make([]byte, 128)
				n, _ := st.Read(buf)
				agentReceived <- string(buf[:n])
				_, _ = st.Write([]byte("PONG_DB"))
				st.Close()
				return
			}
			st.Close()
		}
	}()

	// Register remote node on Server A so it knows db-eu is on gw-eu-west
	serverA.RegisterRemoteNode(protocol.NodeMetadata{
		Hostname:  "db-eu",
		GatewayID: "gw-eu-west",
	}, "gw-eu-west")

	// Client sends command to Server A targeting db-eu.gw-eu-west
	clientConn, ingressConn := net.Pipe()
	defer clientConn.Close()

	execReq := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
		TargetHostname: "db-eu.gw-eu-west",
		Command:        "status",
	}
	reqBytes, _ := json.Marshal(execReq)

	err := serverA.RouteStream("db-eu.gw-eu-west", reqBytes, ingressConn)
	if err != nil {
		t.Fatalf("RouteStream on Server A failed: %v", err)
	}

	_, _ = clientConn.Write([]byte("PING_DB"))

	select {
	case p := <-agentReceived:
		if !strings.Contains(p, "PING_DB") {
			t.Errorf("agent received wrong payload: %q", p)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for agent to receive payload")
	}

	buf := make([]byte, 64)
	n, _ := clientConn.Read(buf)
	if string(buf[:n]) != "PONG_DB" {
		t.Errorf("expected client to receive PONG_DB, got %q", string(buf[:n]))
	}

	// Test loop avoidance: if ExecRequest.Path already contains Server A, route must fail
	loopReq := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
		TargetHostname: "db-eu.gw-eu-west",
		Path:           []string{"gw-us-east"},
	}
	loopBytes, _ := json.Marshal(loopReq)
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()

	err = serverA.RouteStream("db-eu.gw-eu-west", loopBytes, p1)
	if err == nil || !strings.Contains(err.Error(), "circular routing loop") {
		t.Errorf("expected circular routing loop error, got: %v", err)
	}
}

func TestFederatedDNSResolution(t *testing.T) {
	serverA := New(Config{
		Domain:    "fabric.mesh",
		GatewayID: "gw-us-east",
	})
	defer serverA.Close()

	// Register remote node db-1 hosted on gw-eu-west
	serverA.RegisterRemoteNode(protocol.NodeMetadata{
		Hostname:  "db-1",
		GatewayID: "gw-eu-west",
	}, "gw-eu-west")

	proxyIP := "10.100.0.1"

	// 1. Query for db-1.gw-eu-west.fabric.mesh
	m := new(dns.Msg)
	m.SetQuestion("db-1.gw-eu-west.fabric.mesh.", dns.TypeA)
	wire, _ := m.Pack()

	q := protocol.DNSQuery{
		Type:      protocol.TypeDNSQuery,
		SessionID: "sess-dns-fed",
		Data:      base64.StdEncoding.EncodeToString(wire),
	}

	resp := serverA.ResolveDNS(q, proxyIP)
	if resp.RCode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess for federated FQTN, got %d", resp.RCode)
	}

	respWire, _ := base64.StdEncoding.DecodeString(resp.Data)
	mResp := new(dns.Msg)
	_ = mResp.Unpack(respWire)
	if len(mResp.Answer) != 1 {
		t.Fatalf("expected 1 answer for federated DNS query, got %d", len(mResp.Answer))
	}
	aRec := mResp.Answer[0].(*dns.A)
	if aRec.A.String() != proxyIP {
		t.Errorf("expected proxy IP %s, got %s", proxyIP, aRec.A.String())
	}
}

func TestSymmetricPeeringLexicographicalTieBreaker(t *testing.T) {
	serverA := New(Config{GatewayID: "gw-a"})
	defer serverA.Close()

	serverB := New(Config{GatewayID: "gw-b"})
	defer serverB.Close()

	// Connections between A and B
	// C_AtoB: Outbound on A, Inbound on B
	// C_BtoA: Inbound on A, Outbound on B

	// Test on serverA (gw-a < gw-b => prefer Outbound):
	// Case 1: Inbound arrives first, then Outbound arrives -> Outbound replaces Inbound
	sessA_inbound := &GatewayPeerSession{GatewayID: "gw-b", Topology: "core", IsOutbound: false}
	sessA_outbound := &GatewayPeerSession{GatewayID: "gw-b", Topology: "core", IsOutbound: true}

	if err := serverA.RegisterPeer(sessA_inbound); err != nil {
		t.Fatalf("failed to register first peer session: %v", err)
	}
	if err := serverA.RegisterPeer(sessA_outbound); err != nil {
		t.Fatalf("expected outbound session to replace inbound on lower gateway ID: %v", err)
	}
	serverA.peerMu.RLock()
	activePeerA := serverA.peers["gw-b"]
	serverA.peerMu.RUnlock()
	if activePeerA != sessA_outbound {
		t.Errorf("expected serverA to keep outbound session, got: %+v", activePeerA)
	}

	// Case 2: Outbound exists, then Inbound arrives -> Inbound is rejected by tie-breaker
	sessA_inbound2 := &GatewayPeerSession{GatewayID: "gw-b", Topology: "core", IsOutbound: false}
	err := serverA.RegisterPeer(sessA_inbound2)
	if err == nil || !strings.Contains(err.Error(), "tie-breaker") {
		t.Errorf("expected inbound session to be rejected by tie-breaker on serverA, got err: %v", err)
	}
	serverA.peerMu.RLock()
	activePeerA = serverA.peers["gw-b"]
	serverA.peerMu.RUnlock()
	if activePeerA != sessA_outbound {
		t.Errorf("expected serverA to retain outbound session, got: %+v", activePeerA)
	}

	// Test on serverB (gw-b > gw-a => prefer Inbound):
	// Case 3: Outbound arrives first, then Inbound arrives -> Inbound replaces Outbound
	sessB_outbound := &GatewayPeerSession{GatewayID: "gw-a", Topology: "core", IsOutbound: true}
	sessB_inbound := &GatewayPeerSession{GatewayID: "gw-a", Topology: "core", IsOutbound: false}

	if err := serverB.RegisterPeer(sessB_outbound); err != nil {
		t.Fatalf("failed to register first peer session on serverB: %v", err)
	}
	if err := serverB.RegisterPeer(sessB_inbound); err != nil {
		t.Fatalf("expected inbound session to replace outbound on higher gateway ID: %v", err)
	}
	serverB.peerMu.RLock()
	activePeerB := serverB.peers["gw-a"]
	serverB.peerMu.RUnlock()
	if activePeerB != sessB_inbound {
		t.Errorf("expected serverB to keep inbound session, got: %+v", activePeerB)
	}

	// Case 4: Inbound exists, then Outbound arrives -> Outbound is rejected by tie-breaker
	sessB_outbound2 := &GatewayPeerSession{GatewayID: "gw-a", Topology: "core", IsOutbound: true}
	err = serverB.RegisterPeer(sessB_outbound2)
	if err == nil || !strings.Contains(err.Error(), "tie-breaker") {
		t.Errorf("expected outbound session to be rejected by tie-breaker on serverB, got err: %v", err)
	}
	serverB.peerMu.RLock()
	activePeerB = serverB.peers["gw-a"]
	serverB.peerMu.RUnlock()
	if activePeerB != sessB_inbound {
		t.Errorf("expected serverB to retain inbound session, got: %+v", activePeerB)
	}
}

func TestFederatedDNSResolution_FQTNDotFabric(t *testing.T) {
	serverA := New(Config{
		Domain:    "fabric.mesh",
		GatewayID: "gw-us-east",
	})
	defer serverA.Close()

	// Register remote node db-1 hosted on gw-eu-west
	serverA.RegisterRemoteNode(protocol.NodeMetadata{
		Hostname:  "db-1",
		GatewayID: "gw-eu-west",
	}, "gw-eu-west")

	// Register local node web-1
	sMux, cMux := createMockMultiplexers(t)
	defer sMux.Session.Close()
	defer cMux.Session.Close()
	serverA.RegisterNode(protocol.NodeMetadata{
		Hostname: "web-1",
	}, sMux)

	proxyIP := "10.200.0.1"

	tests := []struct {
		name     string
		qname    string
		expected string
	}{
		{"Federated FQTN .fabric", "db-1.gw-eu-west.fabric.", proxyIP},
		{"Federated FQTN .fabric.mesh", "db-1.gw-eu-west.fabric.mesh.", proxyIP},
		{"Local node .fabric", "web-1.fabric.", proxyIP},
		{"Local node .fabric.mesh", "web-1.fabric.mesh.", proxyIP},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, dns.TypeA)
			wire, _ := m.Pack()

			q := protocol.DNSQuery{
				Type:      protocol.TypeDNSQuery,
				SessionID: "sess-test",
				Data:      base64.StdEncoding.EncodeToString(wire),
			}

			resp := serverA.ResolveDNS(q, proxyIP)
			if resp.RCode != dns.RcodeSuccess {
				t.Fatalf("expected RcodeSuccess for query %s, got RCode %d", tc.qname, resp.RCode)
			}

			respWire, _ := base64.StdEncoding.DecodeString(resp.Data)
			mResp := new(dns.Msg)
			_ = mResp.Unpack(respWire)
			if len(mResp.Answer) != 1 {
				t.Fatalf("expected 1 answer for query %s, got %d", tc.qname, len(mResp.Answer))
			}
			aRec, ok := mResp.Answer[0].(*dns.A)
			if !ok {
				t.Fatalf("expected *dns.A record, got %T", mResp.Answer[0])
			}
			if aRec.A.String() != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, aRec.A.String())
			}
		})
	}
}


