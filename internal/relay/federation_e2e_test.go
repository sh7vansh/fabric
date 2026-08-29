package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"
)

func TestFederationFullTopologyE2E(t *testing.T) {
	// 1. Setup 3 Gateways:
	//    - Gateway A (Core US-East)
	//    - Gateway B (Core EU-West)
	//    - Gateway C (Leaf On-Prem/Edge behind NAT)
	gwA := New(Config{
		Domain:    "us.fabric.mesh",
		GatewayID: "gw-us-east",
		Region:    "us-east",
		Token:     "fed-token",
	})
	defer gwA.Close()

	gwB := New(Config{
		Domain:    "eu.fabric.mesh",
		GatewayID: "gw-eu-west",
		Region:    "eu-west",
		Token:     "fed-token",
	})
	defer gwB.Close()

	gwC := New(Config{
		Domain:    "edge.fabric.mesh",
		GatewayID: "gw-edge-leaf",
		Region:    "edge-lab",
		Token:     "fed-token",
	})
	defer gwC.Close()

	// 2. Connect Core A and Core B (Symmetric Peering)
	sMuxB, cMuxA := createMockMultiplexers(t)
	defer sMuxB.Session.Close()
	defer cMuxA.Session.Close()

	peerOnA := &GatewayPeerSession{
		GatewayID: "gw-eu-west",
		Domain:    "eu.fabric.mesh",
		Region:    "eu-west",
		Topology:  "core",
		Mux:       cMuxA,
	}
	gwA.RegisterPeer(peerOnA)

	peerOnB := &GatewayPeerSession{
		GatewayID: "gw-us-east",
		Domain:    "us.fabric.mesh",
		Region:    "us-east",
		Topology:  "core",
		Mux:       sMuxB,
	}
	gwB.RegisterPeer(peerOnB)

	go func() { _ = gwA.ServePeerMux(cMuxA, "", false, "gw-eu-west") }()
	go func() { _ = gwB.ServePeerMux(sMuxB, "", false, "gw-us-east") }()

	// 3. Connect Leaf Gateway C to Core Gateway A (Outbound Reverse Tunnel)
	sMuxA_C, cMuxC_A := createMockMultiplexers(t)
	defer sMuxA_C.Session.Close()
	defer cMuxC_A.Session.Close()

	leafPeerOnA := &GatewayPeerSession{
		GatewayID: "gw-edge-leaf",
		Domain:    "edge.fabric.mesh",
		Region:    "edge-lab",
		Topology:  "leaf",
		Mux:       sMuxA_C,
	}
	gwA.RegisterPeer(leafPeerOnA)

	corePeerOnC := &GatewayPeerSession{
		GatewayID: "gw-us-east",
		Domain:    "us.fabric.mesh",
		Region:    "us-east",
		Topology:  "core",
		Mux:       cMuxC_A,
	}
	gwC.RegisterPeer(corePeerOnC)

	go func() { _ = gwA.ServePeerMux(sMuxA_C, "", true, "gw-edge-leaf") }()
	go func() { _ = gwC.ServePeerMux(cMuxC_A, "", false, "gw-us-east") }()

	// 4. Connect Thread Agents:
	//    - Agent "sensor-1" on Leaf Gateway C
	//    - Agent "db-eu" on Core Gateway B
	//    - Agent "web-us" on Core Gateway A
	agentMuxS_C, agentMuxC_C := createMockMultiplexers(t)
	defer agentMuxC_C.Session.Close()

	_, err := gwC.RegisterNode(protocol.NodeMetadata{
		Hostname: "sensor-1",
		OS:       "linux",
		Arch:     "arm64",
		Tags:     []string{"iot", "edge"},
	}, agentMuxS_C)
	if err != nil {
		t.Fatalf("RegisterNode sensor-1 failed: %v", err)
	}

	agentMuxS_B, agentMuxC_B := createMockMultiplexers(t)
	defer agentMuxC_B.Session.Close()

	_, err = gwB.RegisterNode(protocol.NodeMetadata{
		Hostname: "db-eu",
		OS:       "linux",
		Arch:     "amd64",
		Tags:     []string{"db"},
	}, agentMuxS_B)
	if err != nil {
		t.Fatalf("RegisterNode db-eu failed: %v", err)
	}

	agentMuxS_A, agentMuxC_A := createMockMultiplexers(t)
	defer agentMuxC_A.Session.Close()

	_, err = gwA.RegisterNode(protocol.NodeMetadata{
		Hostname: "web-us",
		OS:       "linux",
		Arch:     "amd64",
		Tags:     []string{"web"},
	}, agentMuxS_A)
	if err != nil {
		t.Fatalf("RegisterNode web-us failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	// 5. Verify Unified Global Listing on Gateway A
	allNodesA := gwA.ListNodes()
	foundSensor := false
	foundDB := false
	foundWeb := false

	for _, n := range allNodesA {
		if n.Hostname == "sensor-1" && n.GatewayID == "gw-edge-leaf" {
			foundSensor = true
		}
		if n.Hostname == "db-eu" && n.GatewayID == "gw-eu-west" {
			foundDB = true
		}
		if n.Hostname == "web-us" && n.GatewayID == "gw-us-east" {
			foundWeb = true
		}
	}

	if !foundSensor {
		t.Errorf("sensor-1 (from leaf gateway) not found on gwA: %+v", allNodesA)
	}
	if !foundDB {
		t.Errorf("db-eu (from peered core gateway) not found on gwA: %+v", allNodesA)
	}
	if !foundWeb {
		t.Errorf("web-us (local thread) not found on gwA: %+v", allNodesA)
	}

	// Verify Peer list on Gateway A
	peersA := gwA.ListPeers()
	if len(peersA) != 2 {
		t.Fatalf("expected 2 peers on gwA, got %d", len(peersA))
	}
	for _, p := range peersA {
		if p.GatewayID == "gw-edge-leaf" && p.Topology != "leaf" {
			t.Errorf("expected leaf topology for gw-edge-leaf, got %s", p.Topology)
		}
		if p.GatewayID == "gw-eu-west" && p.Topology != "core" {
			t.Errorf("expected core topology for gw-eu-west, got %s", p.Topology)
		}
	}

	// 6. Test Cross-Gateway Execution: Client on Gateway A executes on Leaf Agent "sensor-1"
	agentSensorReceived := make(chan string, 1)
	go func() {
		for {
			st, err := agentMuxC_C.Session.Accept()
			if err != nil {
				return
			}
			var req protocol.ExecRequest
			dec := json.NewDecoder(st)
			if err := dec.Decode(&req); err == nil && req.Type == protocol.TypeExecRequest {
				agentReader := io.MultiReader(dec.Buffered(), st)
				buf := make([]byte, 128)
				n, _ := io.ReadAtLeast(agentReader, buf, len("CMD_READ"))
				agentSensorReceived <- string(buf[:n])
				_, _ = st.Write([]byte("DATA_FROM_EDGE_SENSOR"))
				st.Close()
				return
			}
			st.Close()
		}
	}()

	clientConn, streamConn := net.Pipe()
	defer clientConn.Close()

	execReq := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
		TargetHostname: "sensor-1.gw-edge-leaf",
		Command:        "read-sensor",
	}
	execBytes, _ := json.Marshal(execReq)

	err = gwA.RouteStream("sensor-1.gw-edge-leaf", execBytes, streamConn)
	if err != nil {
		t.Fatalf("gwA.RouteStream to sensor-1.gw-edge-leaf failed: %v", err)
	}

	_, _ = clientConn.Write([]byte("CMD_READ"))

	select {
	case p := <-agentSensorReceived:
		if !strings.Contains(p, "CMD_READ") {
			t.Errorf("sensor-1 received wrong payload: %q", p)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for edge sensor agent to receive routed exec stream")
	}

	buf := make([]byte, 64)
	n, _ := io.ReadAtLeast(clientConn, buf, len("DATA_FROM_EDGE_SENSOR"))
	if string(buf[:n]) != "DATA_FROM_EDGE_SENSOR" {
		t.Errorf("expected DATA_FROM_EDGE_SENSOR, got %q", string(buf[:n]))
	}

	// 7. Test Cross-Gateway Tar Copy Stream: Client on Gateway A copies to db-eu on Gateway B
	agentDBReceived := make(chan string, 1)
	go func() {
		for {
			st, err := agentMuxC_B.Session.Accept()
			if err != nil {
				return
			}
			var req protocol.CopyRequest
			dec := json.NewDecoder(st)
			if err := dec.Decode(&req); err == nil && req.Type == protocol.TypeCopyRequest {
				agentReader := io.MultiReader(dec.Buffered(), st)
				buf := make([]byte, 128)
				n, _ := io.ReadAtLeast(agentReader, buf, len("TAR_BYTES_STREAM"))
				agentDBReceived <- string(buf[:n])
				_, _ = st.Write([]byte("ACK_TAR_SAVED"))
				st.Close()
				return
			}
			st.Close()
		}
	}()

	cpClientConn, cpStreamConn := net.Pipe()
	defer cpClientConn.Close()

	cpReq := protocol.CopyRequest{
		Type:           protocol.TypeCopyRequest,
		TargetHostname: "db-eu.gw-eu-west",
		Direction:      "upload",
		RemotePath:     "/data/backup.sql",
	}
	cpBytes, _ := json.Marshal(cpReq)

	err = gwA.RouteStream("db-eu.gw-eu-west", cpBytes, cpStreamConn)
	if err != nil {
		t.Fatalf("gwA.RouteStream copy failed: %v", err)
	}

	_, _ = cpClientConn.Write([]byte("TAR_BYTES_STREAM"))

	select {
	case p := <-agentDBReceived:
		if !strings.Contains(p, "TAR_BYTES_STREAM") {
			t.Errorf("db-eu received wrong copy payload: %q", p)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for db agent to receive copy stream")
	}

	cpAckBuf := make([]byte, 64)
	nCp, _ := io.ReadAtLeast(cpClientConn, cpAckBuf, len("ACK_TAR_SAVED"))
	if string(cpAckBuf[:nCp]) != "ACK_TAR_SAVED" {
		t.Errorf("expected ACK_TAR_SAVED, got %q", string(cpAckBuf[:nCp]))
	}

	// 8. Test Cross-Gateway TCP Port Proxying: Forward port to db-eu:5432
	agentProxyReceived := make(chan string, 1)
	go func() {
		for {
			st, err := agentMuxC_B.Session.Accept()
			if err != nil {
				return
			}
			var req protocol.ProxyRequest
			dec := json.NewDecoder(st)
			if err := dec.Decode(&req); err == nil && req.Type == protocol.TypeProxyRequest {
				agentReader := io.MultiReader(dec.Buffered(), st)
				buf := make([]byte, 128)
				n, _ := io.ReadAtLeast(agentReader, buf, len("PGSQL_STARTUP"))
				agentProxyReceived <- string(buf[:n])
				_, _ = st.Write([]byte("PGSQL_READY"))
				st.Close()
				return
			}
			st.Close()
		}
	}()

	proxyClientConn, proxyStreamConn := net.Pipe()
	defer proxyClientConn.Close()

	proxyReq := protocol.ProxyRequest{
		Type:           protocol.TypeProxyRequest,
		TargetHostname: "db-eu.gw-eu-west",
		TargetHost:     "127.0.0.1",
		TargetPort:     5432,
	}
	proxyBytes, _ := json.Marshal(proxyReq)

	err = gwA.RouteProxyStream("db-eu.gw-eu-west", proxyBytes, proxyStreamConn)
	if err != nil {
		t.Fatalf("gwA.RouteProxyStream failed: %v", err)
	}

	_, _ = proxyClientConn.Write([]byte("PGSQL_STARTUP"))

	select {
	case p := <-agentProxyReceived:
		if !strings.Contains(p, "PGSQL_STARTUP") {
			t.Errorf("db-eu proxy received wrong payload: %q", p)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for db agent proxy stream")
	}

	proxyReplyBuf := make([]byte, 64)
	nProxy, _ := io.ReadAtLeast(proxyClientConn, proxyReplyBuf, len("PGSQL_READY"))
	if !bytes.Contains(proxyReplyBuf[:nProxy], []byte("PGSQL_READY")) {
		t.Errorf("expected PGSQL_READY, got %q", string(proxyReplyBuf[:nProxy]))
	}

	// 9. Disconnect Leaf Gateway C -> check automatic route withdrawal on Gateway A
	gwC.Close()
	time.Sleep(100 * time.Millisecond)

	nodesAfterLeafDisconnect := gwA.ListNodes()
	for _, n := range nodesAfterLeafDisconnect {
		if n.Hostname == "sensor-1" {
			t.Errorf("expected sensor-1 routes to be withdrawn after gwC closed, but still present")
		}
	}
	peersAfterLeafDisconnect := gwA.ListPeers()
	if len(peersAfterLeafDisconnect) != 1 || peersAfterLeafDisconnect[0].GatewayID != "gw-eu-west" {
		t.Errorf("expected only gw-eu-west in peers after leaf disconnect, got %+v", peersAfterLeafDisconnect)
	}
}
