package meshdns

import (
	"fabric/internal/protocol"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestHostsBlock(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "hosts")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.Write([]byte("127.0.0.1 localhost\n::1 localhost\n"))
	tmpFile.Close()

	HostsFilePath = tmpFile.Name()

	nodes := []protocol.NodeMetadata{
		{Hostname: "node-1"},
		{Hostname: "node-2"},
	}

	UpdateHostsBlock(nodes, "fabric.mesh", "http://127.0.0.1:8080")

	content, _ := ioutil.ReadFile(HostsFilePath)
	contentStr := string(content)

	if !strings.Contains(contentStr, "# BEGIN FABRIC MESH") {
		t.Errorf("Expected # BEGIN FABRIC MESH block")
	}
	if !strings.Contains(contentStr, "127.0.0.1 node-1.fabric.mesh") {
		t.Errorf("Expected node-1 in hosts, got:\n%s", contentStr)
	}

	CleanHostsBlock()

	content, _ = ioutil.ReadFile(HostsFilePath)
	contentStr = string(content)

	if strings.Contains(contentStr, "# BEGIN FABRIC MESH") {
		t.Errorf("Expected # BEGIN FABRIC MESH block to be removed")
	}
	if strings.Contains(contentStr, "node-1.fabric.mesh") {
		t.Errorf("Expected node-1 to be removed")
	}
}
