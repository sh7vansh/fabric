package protocol

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

const (
	TypeProxyRequest  EnvelopeType = "proxy_request"
	TypeProxyResponse EnvelopeType = "proxy_response"
)

type ProxyRequest struct {
	Type           EnvelopeType `json:"type"`
	TargetHostname string       `json:"target_hostname,omitempty"`
	TargetHost     string       `json:"target_host,omitempty"`
	TargetPort     int          `json:"target_port,omitempty"`
}

type ProxyResponse struct {
	Type    EnvelopeType `json:"type"`
	Success bool         `json:"success"`
	Error   string       `json:"error,omitempty"`
}

// ValidateProxyDestination checks that the requested target host and port are valid and safe.
func ValidateProxyDestination(host string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}

	trimmedHost := strings.TrimSpace(host)
	if trimmedHost == "" {
		trimmedHost = "127.0.0.1"
	}

	// Check for blocked link-local / metadata addresses
	ip := net.ParseIP(trimmedHost)
	if ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Equal(net.ParseIP("169.254.169.254")) {
			return "", fmt.Errorf("proxy destination %s is restricted (link-local/cloud metadata)", trimmedHost)
		}
	} else if strings.EqualFold(trimmedHost, "instance-data") || strings.EqualFold(trimmedHost, "metadata.google.internal") {
		return "", fmt.Errorf("proxy destination %s is restricted (cloud metadata hostname)", trimmedHost)
	}

	return fmt.Sprintf("%s:%d", trimmedHost, port), nil
}

func Proxy(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
	}()
	wg.Wait()
}
