package cli

import (
	"testing"
)

func TestParsePathSpec(t *testing.T) {
	tests := []struct {
		input       string
		expectedNode string
		expectedPath string
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
