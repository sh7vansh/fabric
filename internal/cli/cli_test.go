package cli

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"fabric/internal/protocol"
)

func TestParsePathSpec(t *testing.T) {
	tests := []struct {
		input          string
		expectedNode   string
		expectedPath   string
		expectedRemote bool
	}{
		{"local/file.txt", "", "local/file.txt", false},
		{"worker-1:/var/log", "worker-1", "/var/log", true},
		{"node-a:file.tar", "node-a", "file.tar", true},
		{":/tmp", "", "/tmp", true},
	}

	for _, tt := range tests {
		node, path, isRemote := parsePathSpec(tt.input)
		if node != tt.expectedNode || path != tt.expectedPath || isRemote != tt.expectedRemote {
			t.Errorf("parsePathSpec(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.input, node, path, isRemote, tt.expectedNode, tt.expectedPath, tt.expectedRemote)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	lp, rp, err := ParsePortSpec("8080:80")
	if err != nil || lp != 8080 || rp != 80 {
		t.Fatalf("ParsePortSpec failed: %v, lp=%d, rp=%d", err, lp, rp)
	}

	_, _, err = ParsePortSpec("invalid")
	if err == nil {
		t.Errorf("expected error for invalid spec")
	}
}

func filterNodesByTag(nodes []protocol.NodeMetadata, tag string) []protocol.NodeMetadata {
	if tag == "" {
		return nodes
	}
	var filtered []protocol.NodeMetadata
	for _, n := range nodes {
		for _, t := range n.Tags {
			if t == tag {
				filtered = append(filtered, n)
				break
			}
		}
	}
	return filtered
}

func TestFilterNodesByTag(t *testing.T) {
	nodes := []protocol.NodeMetadata{
		{ID: "node1", Tags: []string{"web", "prod"}},
		{ID: "node2", Tags: []string{"db", "prod"}},
		{ID: "node3", Tags: []string{"web", "staging"}},
	}

	webNodes := filterNodesByTag(nodes, "web")
	if len(webNodes) != 2 {
		t.Errorf("expected 2 web nodes, got %d", len(webNodes))
	}

	dbNodes := filterNodesByTag(nodes, "db")
	if len(dbNodes) != 1 || dbNodes[0].ID != "node2" {
		t.Errorf("expected node2 for db tag, got %+v", dbNodes)
	}

	unknownNodes := filterNodesByTag(nodes, "gpu")
	if len(unknownNodes) != 0 {
		t.Errorf("expected 0 gpu nodes, got %d", len(unknownNodes))
	}
}

func TestParseTags(t *testing.T) {
	tags := parseTags("web, prod,  staging ,")
	if len(tags) != 3 || tags[0] != "web" || tags[1] != "prod" || tags[2] != "staging" {
		t.Errorf("unexpected parsed tags: %v", tags)
	}

	emptyTags := parseTags("")
	if emptyTags != nil {
		t.Errorf("expected nil for empty tag string, got: %v", emptyTags)
	}
}

func TestGetStandalonePaths(t *testing.T) {
	runDir, pidFile, sup, bin := getStandalonePaths("node")
	if runDir == "" || pidFile == "" || sup == "" || bin == "" {
		t.Errorf("getStandalonePaths returned empty paths: %s, %s, %s, %s", runDir, pidFile, sup, bin)
	}
}

func TestLinePrefixedWriter(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex

	w := NewLinePrefixedWriter("worker-1", &buf, &mu)

	// Write full line
	w.Write([]byte("line 1\n"))
	if buf.String() != "[worker-1] line 1\n" {
		t.Errorf("expected '[worker-1] line 1\\n', got %q", buf.String())
	}
	buf.Reset()

	// Write partial line + flush
	w.Write([]byte("partial line"))
	if buf.Len() != 0 {
		t.Errorf("expected buffer to hold partial line until newline or flush")
	}
	w.Flush()
	if buf.String() != "[worker-1] partial line\n" {
		t.Errorf("expected '[worker-1] partial line\\n', got %q", buf.String())
	}
	buf.Reset()

	// Write multiple lines across chunks
	w.Write([]byte("chunk 1 "))
	w.Write([]byte("chunk 2\nchunk 3\n"))
	expected := "[worker-1] chunk 1 chunk 2\n[worker-1] chunk 3\n"
	if buf.String() != expected {
		t.Errorf("expected %q, got %q", expected, buf.String())
	}
}

func TestLinePrefixedWriter_Concurrent(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex

	w1 := NewLinePrefixedWriter("node-a", &buf, &mu)
	w2 := NewLinePrefixedWriter("node-b", &buf, &mu)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			w1.Write([]byte("node-a message\n"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			w2.Write([]byte("node-b message\n"))
		}
	}()

	wg.Wait()
	w1.Flush()
	w2.Flush()

	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 output lines, got %d:\n%s", len(lines), out)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "[node-a] ") && !strings.HasPrefix(l, "[node-b] ") {
			t.Errorf("unexpected line format: %q", l)
		}
	}
}

func TestMultiNodeTagResolution(t *testing.T) {
	allNodes := []protocol.NodeMetadata{
		{Hostname: "web-1", Tags: []string{"web", "prod"}},
		{Hostname: "web-2", Tags: []string{"web", "staging"}},
		{Hostname: "db-1", Tags: []string{"db", "prod"}},
	}

	// 1. Tag "web" should match 2 nodes
	var webTargets []protocol.NodeMetadata
	for _, n := range allNodes {
		for _, tag := range n.Tags {
			if tag == "web" {
				webTargets = append(webTargets, n)
				break
			}
		}
	}
	if len(webTargets) != 2 {
		t.Fatalf("expected 2 web nodes, got %d", len(webTargets))
	}

	// 2. Tag "prod" should match 2 nodes
	var prodTargets []protocol.NodeMetadata
	for _, n := range allNodes {
		for _, tag := range n.Tags {
			if tag == "prod" {
				prodTargets = append(prodTargets, n)
				break
			}
		}
	}
	if len(prodTargets) != 2 {
		t.Fatalf("expected 2 prod nodes, got %d", len(prodTargets))
	}

	// 3. Unknown tag
	var missing []protocol.NodeMetadata
	for _, n := range allNodes {
		for _, tag := range n.Tags {
			if tag == "gpu" {
				missing = append(missing, n)
				break
			}
		}
	}
	if len(missing) != 0 {
		t.Fatalf("expected 0 matching nodes, got %d", len(missing))
	}
}
