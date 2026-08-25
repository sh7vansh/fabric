package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"
	"fabric/internal/relay"
)

func setupTestMesh(t *testing.T) (*httptest.Server, *relay.Relay) {
	testToken := "test-token-thread"
	r := relay.New(relay.Config{
		Domain:   "fabric.mesh",
		Token:    testToken,
		PingFreq: 0,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/nodes", func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		if auth != "Bearer "+testToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.ListNodes())
	})

	mux.HandleFunc("/nodes/", func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		if auth != "Bearer "+testToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		hostname := req.URL.Path[len("/nodes/"):]
		meta, ok := r.GetNode(hostname)
		if !ok {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})

	ts := httptest.NewServer(mux)
	return ts, r
}

func TestThreadCommandsAndDeprecations(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	ts, r := setupTestMesh(t)
	defer ts.Close()
	defer r.Close()

	// Register some test nodes/threads in the relay
	r.RegisterNode(protocol.NodeMetadata{
		ID:          "node-1",
		Hostname:    "worker-1",
		RemoteIP:    "192.168.1.10",
		Status:      "online",
		Tags:        []string{"web", "prod"},
		OS:          "linux",
		Arch:        "amd64",
		Domain:      "fabric.mesh",
		ConnectedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil)

	r.RegisterNode(protocol.NodeMetadata{
		ID:          "node-2",
		Hostname:    "worker-2",
		RemoteIP:    "192.168.1.11",
		Status:      "online",
		Tags:        []string{"db", "prod"},
		OS:          "linux",
		Arch:        "arm64",
		Domain:      "fabric.mesh",
		ConnectedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil)

	// Set CLI flags for the server
	serverFlag = ts.URL
	tokenFlag = "test-token-thread"
	defer func() {
		serverFlag = ""
		tokenFlag = ""
	}()

	var stderrBuf bytes.Buffer
	SetDeprecationWriter(&stderrBuf)
	defer SetDeprecationWriter(nil)

	// 1. Test `fabric thread ls`
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"thread", "ls"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("thread ls failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "THREAD") || !strings.Contains(out, "worker-1") || !strings.Contains(out, "worker-2") {
			t.Errorf("expected thread table with THREAD header and workers, got:\n%s", out)
		}
	}

	// 2. Test `fabric thread ls -q`
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "ls", "-q"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("thread ls -q failed: %v", err)
		}
		out := stdoutBuf.String()
		lines := strings.Fields(strings.TrimSpace(out))
		if len(lines) < 2 {
			t.Errorf("expected at least 2 thread names, got:\n%s", out)
		}
	}

	// 3. Test `fabric thread ls --format json`
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "ls", "--format", "json"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("thread ls --format json failed: %v", err)
		}
		var list []protocol.NodeMetadata
		if err := json.Unmarshal(stdoutBuf.Bytes(), &list); err != nil {
			t.Fatalf("failed to unmarshal JSON output: %v", err)
		}
		if len(list) < 2 {
			t.Errorf("expected >= 2 threads in JSON, got %d", len(list))
		}
	}

	// 4. Test `fabric thread ls --tag db`
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "ls", "-l", "db"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("thread ls -l db failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "worker-2") || strings.Contains(out, "worker-1") {
			t.Errorf("expected only worker-2 for tag db, got:\n%s", out)
		}
	}

	// 5. Test `fabric thread inspect worker-1`
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"thread", "inspect", "worker-1"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("thread inspect failed: %v", err)
		}
		var list []protocol.NodeMetadata
		if err := json.Unmarshal(stdoutBuf.Bytes(), &list); err != nil {
			t.Fatalf("failed to parse inspect JSON: %v", err)
		}
		if len(list) != 1 || list[0].Hostname != "worker-1" {
			t.Errorf("expected inspect output for worker-1, got: %+v", list)
		}
	}

	// 6. Test `fabric ps` (shorthand for `fabric thread ls`)
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"ps"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("ps failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "THREAD") || !strings.Contains(out, "worker-1") {
			t.Errorf("expected ps to output thread list, got:\n%s", out)
		}
	}

	// 7. Test `fabric node ls` legacy alias with deprecation warning
	{
		stderrBuf.Reset()
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"node", "ls"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("node ls failed: %v", err)
		}
		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric node' is deprecated. Use 'fabric thread' instead.") &&
			!strings.Contains(stderrBuf.String(), "Warning: 'fabric node ls' is deprecated. Use 'fabric thread ls' instead.") {
			t.Errorf("expected deprecation warning in stderr, got: %s", stderrBuf.String())
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "THREAD") || !strings.Contains(out, "worker-1") {
			t.Errorf("expected node ls to execute thread ls, got:\n%s", out)
		}
	}

	// 8. Test `fabric node inspect worker-1` legacy alias with deprecation warning
	{
		stderrBuf.Reset()
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetErr(&stderrBuf)
		rootCmd.SetArgs([]string{"node", "inspect", "worker-1"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("node inspect failed: %v", err)
		}
		if !strings.Contains(stderrBuf.String(), "Warning: 'fabric node' is deprecated. Use 'fabric thread' instead.") &&
			!strings.Contains(stderrBuf.String(), "Warning: 'fabric node inspect' is deprecated. Use 'fabric thread inspect' instead.") {
			t.Errorf("expected deprecation warning in stderr, got: %s", stderrBuf.String())
		}
		var list []protocol.NodeMetadata
		if err := json.Unmarshal(stdoutBuf.Bytes(), &list); err != nil {
			t.Fatalf("failed to parse inspect JSON: %v", err)
		}
		if len(list) != 1 || list[0].Hostname != "worker-1" {
			t.Errorf("expected inspect output for worker-1, got: %+v", list)
		}
	}
}
