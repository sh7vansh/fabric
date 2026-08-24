package meshdns

import (
	"fabric/internal/protocol"
	"io/ioutil"
	"net"
	"net/url"
	"strings"
)

var HostsFilePath = "/etc/hosts"

func UpdateHostsBlock(nodes []protocol.NodeMetadata, domain, socketURL string) {
	u, err := url.Parse(socketURL)
	if err != nil {
		return
	}
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return
	}
	socketIP := ips[0].String()

	content, err := ioutil.ReadFile(HostsFilePath)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inBlock := false

	for _, line := range lines {
		if strings.TrimSpace(line) == "# BEGIN FABRIC MESH" {
			inBlock = true
			continue
		}
		if strings.TrimSpace(line) == "# END FABRIC MESH" {
			inBlock = false
			continue
		}
		if !inBlock {
			newLines = append(newLines, line)
		}
	}

	// Remove trailing empty lines before appending
	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	newLines = append(newLines, "", "# BEGIN FABRIC MESH")
	for _, n := range nodes {
		// e.g. 192.168.1.100 node-1.fabric.mesh
		newLines = append(newLines, socketIP+" "+n.Hostname+"."+domain)
	}
	newLines = append(newLines, "# END FABRIC MESH")

	ioutil.WriteFile(HostsFilePath, []byte(strings.Join(newLines, "\n")), 0644)
}

func CleanHostsBlock() {
	content, err := ioutil.ReadFile(HostsFilePath)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inBlock := false
	changed := false

	for _, line := range lines {
		if strings.TrimSpace(line) == "# BEGIN FABRIC MESH" {
			inBlock = true
			changed = true
			continue
		}
		if strings.TrimSpace(line) == "# END FABRIC MESH" {
			inBlock = false
			continue
		}
		if !inBlock {
			newLines = append(newLines, line)
		}
	}

	if changed {
		for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
			newLines = newLines[:len(newLines)-1]
		}
		newLines = append(newLines, "")
		ioutil.WriteFile(HostsFilePath, []byte(strings.Join(newLines, "\n")), 0644)
	}
}
