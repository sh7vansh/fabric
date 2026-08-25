package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"
)

func TestCoreOperationsThreadTerminology(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	ts, r := setupTestMesh(t)
	defer ts.Close()
	defer r.Close()

	r.RegisterNode(protocol.NodeMetadata{
		ID:          "node-1",
		Hostname:    "worker-1",
		RemoteIP:    "192.168.1.10",
		Status:      "online",
		Tags:        []string{"web"},
		Domain:      "fabric.mesh",
		ConnectedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil)

	serverFlag = ts.URL
	tokenFlag = "test-token-thread"
	defer func() {
		serverFlag = ""
		tokenFlag = ""
	}()

	// 1. Test fabric cp validation errors
	{
		err := runCp(cpCmd, []string{"local.txt", "other.txt"})
		if err == nil || !strings.Contains(err.Error(), "remote thread") {
			t.Errorf("expected error mentioning remote thread, got: %v", err)
		}

		err = runCp(cpCmd, []string{"worker-1:/a", "worker-2:/b"})
		if err == nil || !strings.Contains(err.Error(), "thread-to-thread") {
			t.Errorf("expected error mentioning thread-to-thread, got: %v", err)
		}
	}

	// 2. Test fabric exec non-existent thread error message
	{
		client := NewClient(GetConfig())
		_, err := client.GetNode("ghost-thread")
		if err == nil || !strings.Contains(err.Error(), "thread 'ghost-thread' not found") {
			t.Errorf("expected 'thread 'ghost-thread' not found', got: %v", err)
		}
	}

	// 3. Test fabric port inspection
	{
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"port", "worker-1"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("port inspection failed: %v", err)
		}
		out := stdoutBuf.String()
		if !strings.Contains(out, "worker-1.fabric.mesh") {
			t.Errorf("expected port inspection output for worker-1, got: %s", out)
		}
	}
}
