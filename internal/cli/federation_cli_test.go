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

func TestThreadLsMultiClusterAndPeerFiltering(t *testing.T) {
	mockNodes := []protocol.NodeMetadata{
		{
			ID:        "web-us",
			Hostname:  "web-us",
			GatewayID: "gw-us-east",
			Status:    "online",
			Tags:      []string{"web", "prod"},
			RemoteIP:  "10.0.1.5",
			Domain:    "us-east.fabric",
		},
		{
			ID:        "db-eu",
			Hostname:  "db-eu",
			GatewayID: "gw-eu-west",
			Status:    "online",
			Tags:      []string{"db"},
			RemoteIP:  "10.0.2.10",
			Domain:    "eu-west.fabric",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockNodes)
			return
		}
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "2.4.1", "domain": "fabric.mesh"})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	serverFlag = ts.URL
	tokenFlag = "test-token"
	defer func() {
		serverFlag = ""
		tokenFlag = ""
	}()

	// 1. Test listing all threads displays SERVER column
	var bufAll bytes.Buffer
	threadLsCmd.SetOut(&bufAll)
	defer threadLsCmd.SetOut(nil)
	err := runThreadLs(threadLsCmd, []string{})
	if err != nil {
		t.Fatalf("runThreadLs failed: %v", err)
	}

	outputAll := bufAll.String()
	if !strings.Contains(outputAll, "SERVER") || !strings.Contains(outputAll, "gw-us-east") || !strings.Contains(outputAll, "gw-eu-west") {
		t.Errorf("unexpected thread ls table output:\n%s", outputAll)
	}

	// 2. Test filtering by peer
	peerFilterFlag = "gw-eu-west"
	var bufFiltered bytes.Buffer
	threadLsCmd.SetOut(&bufFiltered)
	err = runThreadLs(threadLsCmd, []string{})
	if err != nil {
		t.Fatalf("runThreadLs with --peer failed: %v", err)
	}

	outputFiltered := bufFiltered.String()
	if !strings.Contains(outputFiltered, "db-eu") {
		t.Errorf("expected db-eu in filtered output:\n%s", outputFiltered)
	}
	if strings.Contains(outputFiltered, "web-us") {
		t.Errorf("web-us should have been filtered out by --peer gw-eu-west:\n%s", outputFiltered)
	}
}
