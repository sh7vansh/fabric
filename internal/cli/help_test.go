package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpCommandOutput(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute(--help) returned error: %v", err)
	}

	output := buf.String()

	// Verify command groups exist in help output
	expectedGroups := []string{
		"Core Execution Commands:",
		"Thread Management Commands:",
		"Mesh & Networking Commands:",
		"System & Lifecycle Commands:",
		"Help Topics & Guides:",
	}

	for _, group := range expectedGroups {
		if !strings.Contains(output, group) {
			t.Errorf("Expected help output to contain group header %q, but got:\n%s", group, output)
		}
	}

	// Verify topics are present
	expectedTopics := []string{"architecture", "networking", "security", "workflows", "threads", "stitch-guide"}
	for _, topic := range expectedTopics {
		if !strings.Contains(output, topic) {
			t.Errorf("Expected help output to contain topic %q, but got:\n%s", topic, output)
		}
	}

	// Verify global flags are listed
	if !strings.Contains(output, "--server") || !strings.Contains(output, "--token") {
		t.Errorf("Expected help output to contain global persistent flags (--server, --token)")
	}
}

func TestHelpTopicsExecution(t *testing.T) {
	topics := []string{"architecture", "networking", "security", "workflows", "threads", "stitch-guide"}

	for _, topic := range topics {
		t.Run(topic, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{topic, "--help"})

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("Failed to execute help for topic %s: %v", topic, err)
			}

			output := buf.String()
			if len(output) == 0 {
				t.Errorf("Expected topic %s help to produce output", topic)
			}
			if strings.Contains(output, "Global Flags:") {
				t.Errorf("Expected clean topic %s guide without global flags dump, got:\n%s", topic, output)
			}
		})
	}
}
