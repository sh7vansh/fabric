package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fabric/internal/protocol"
)

func TestPeerCLICommands(t *testing.T) {
	// Mock Fabric server HTTP endpoint
	mockPeers := []protocol.GatewayPeerInfo{
		{
			GatewayID:   "gw-eu-west",
			Domain:      "eu-west.fabric",
			Region:      "eu-west",
			Topology:    "core",
			RTT:         "24ms",
			ThreadCount: 3,
			Status:      "connected",
			Endpoint:    "wss://eu-west.fabric.io:443",
		},
		{
			GatewayID:   "gw-onprem",
			Domain:      "onprem.fabric",
			Region:      "edge-lab",
			Topology:    "leaf",
			RTT:         "12ms",
			ThreadCount: 5,
			Status:      "connected",
			Endpoint:    "wss://core.fabric.io:443",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/peers" {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(mockPeers)
				return
			}
			if r.Method == http.MethodPost {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				return
			}
		}
		if r.URL.Path == "/peers/gw-eu-west" {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(mockPeers[0])
				return
			}
			if r.Method == http.MethodDelete {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// 1. Test Client methods directly
	cfg := &Config{
		Host:  ts.URL,
		Token: "test-token",
	}
	client := NewClient(cfg)

	peers, err := client.ListPeers()
	if err != nil {
		t.Fatalf("client.ListPeers() failed: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].GatewayID != "gw-eu-west" || peers[1].Topology != "leaf" {
		t.Errorf("unexpected peers: %+v", peers)
	}

	info, err := client.GetPeer("gw-eu-west")
	if err != nil {
		t.Fatalf("client.GetPeer() failed: %v", err)
	}
	if info.GatewayID != "gw-eu-west" || info.Region != "eu-west" {
		t.Errorf("unexpected peer info: %+v", info)
	}

	err = client.AddPeer("wss://new-peer.fabric.io:443")
	if err != nil {
		t.Fatalf("client.AddPeer() failed: %v", err)
	}

	err = client.RemovePeer("gw-eu-west")
	if err != nil {
		t.Fatalf("client.RemovePeer() failed: %v", err)
	}

	// 2. Test fabric peer ls command output
	serverFlag = ts.URL
	tokenFlag = "test-token"
	defer func() {
		serverFlag = ""
		tokenFlag = ""
	}()

	var buf bytes.Buffer
	peerLsCmd.SetOut(&buf)
	defer peerLsCmd.SetOut(nil)
	err = runPeerLs(peerLsCmd, []string{})
	if err != nil {
		t.Fatalf("runPeerLs failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SERVER ID") || !strings.Contains(output, "gw-eu-west") || !strings.Contains(output, "LEAF") {
		t.Errorf("unexpected peer ls table output:\n%s", output)
	}

	// 3. Test fabric peer ls -q (quiet) output
	peerQuietFlag = true
	var bufQuiet bytes.Buffer
	peerLsCmd.SetOut(&bufQuiet)
	err = runPeerLs(peerLsCmd, []string{})
	if err != nil {
		t.Fatalf("runPeerLs -q failed: %v", err)
	}
	outputQuiet := bufQuiet.String()
	if !strings.Contains(outputQuiet, "gw-eu-west") || !strings.Contains(outputQuiet, "gw-onprem") || strings.Contains(outputQuiet, "SERVER ID") {
		t.Errorf("unexpected peer ls -q output:\n%s", outputQuiet)
	}
}
