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
		"Mesh & Networking Commands:",
		"Node & Cluster Management Commands:",
		"System & Service Commands:",
		"Help Topics & Guides:",
	}

	for _, group := range expectedGroups {
		if !strings.Contains(output, group) {
			t.Errorf("Expected help output to contain group header %q, but got:\n%s", group, output)
		}
	}

	// Verify topics are present
	expectedTopics := []string{"architecture", "networking", "security", "workflows"}
	for _, topic := range expectedTopics {
		if !strings.Contains(output, topic) {
			t.Errorf("Expected help output to contain topic %q, but got:\n%s", topic, output)
		}
	}

	// Verify global flags are listed
	if !strings.Contains(output, "--host") || !strings.Contains(output, "--token") {
		t.Errorf("Expected help output to contain global persistent flags (--host, --token)")
	}
}

func TestHelpTopicsExecution(t *testing.T) {
	topics := []string{"architecture", "networking", "security", "workflows"}

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
			if !strings.Contains(output, "Usage:") {
				t.Errorf("Expected topic %s help to contain Usage block, got:\n%s", topic, output)
			}
		})
	}
}
