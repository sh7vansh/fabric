package provision

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func startMockSSHServer(t *testing.T, banner string) (net.Listener, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprintf(c, "%s\r\n", banner)
				time.Sleep(100 * time.Millisecond)
			}(conn)
		}
	}()

	return ln, port
}

func startMockHTTPServer(t *testing.T) (net.Listener, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock HTTP listener: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			}(conn)
		}
	}()

	return ln, port
}

func TestProbeSSH(t *testing.T) {
	sshLn, sshPort := startMockSSHServer(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2")
	defer sshLn.Close()

	httpLn, httpPort := startMockHTTPServer(t)
	defer httpLn.Close()

	host, err := ProbeSSH("127.0.0.1", sshPort, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeSSH valid failed: %v", err)
	}
	if host.Port != sshPort {
		t.Errorf("Port = %d, want %d", host.Port, sshPort)
	}
	if host.CleanBanner != "OpenSSH_9.2p1 Debian-2" {
		t.Errorf("CleanBanner = %q, want %q", host.CleanBanner, "OpenSSH_9.2p1 Debian-2")
	}

	_, err = ProbeSSH("127.0.0.1", httpPort, 500*time.Millisecond)
	if err == nil {
		t.Errorf("ProbeSSH on HTTP port should have failed")
	}

	// Unreachable port test
	_, err = ProbeSSH("127.0.0.1", 1, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("expected connection error for closed port, got nil")
	}
	if !strings.Contains(err.Error(), "firewall") || !strings.Contains(err.Error(), "port 1/TCP") {
		t.Errorf("expected firewall diagnostic in error, got: %v", err)
	}
}

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantCount   int
		firstIP     string
		lastIP      string
		expectError bool
	}{
		{
			name:        "Standard /30 subnet",
			input:       "192.168.1.0/30",
			wantCount:   2,
			firstIP:     "192.168.1.1",
			lastIP:      "192.168.1.2",
			expectError: false,
		},
		{
			name:        "Single IP",
			input:       "192.168.1.50",
			wantCount:   1,
			firstIP:     "192.168.1.50",
			lastIP:      "192.168.1.50",
			expectError: false,
		},
		{
			name:        "IPv4 single octet range",
			input:       "192.168.1.10-15",
			wantCount:   6,
			firstIP:     "192.168.1.10",
			lastIP:      "192.168.1.15",
			expectError: false,
		},
		{
			name:        "Invalid CIDR notation",
			input:       "999.999.999.999/24",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := ParseTargets(tt.input, "127.0.0.1/32")
			if (err != nil) != tt.expectError {
				t.Fatalf("ParseTargets(%q) error = %v, expectError = %v", tt.input, err, tt.expectError)
			}
			if tt.expectError {
				return
			}
			if len(targets) != tt.wantCount {
				t.Errorf("count = %d, want %d", len(targets), tt.wantCount)
			}
		})
	}
}

func TestScanTargetsConcurrent(t *testing.T) {
	sshLn, port := startMockSSHServer(t, "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
	defer sshLn.Close()

	targets := []string{"127.0.0.1"}
	opts := ScanOptions{
		Ports:       []int{port},
		Concurrency: 5,
		Timeout:     300 * time.Millisecond,
	}

	discovered, err := ScanTargets(targets, opts, nil)
	if err != nil {
		t.Fatalf("ScanTargets failed: %v", err)
	}

	if len(discovered) != 1 {
		t.Fatalf("Expected 1 discovered host, got %d", len(discovered))
	}
	if discovered[0].Port != port {
		t.Errorf("Port = %d, want %d", discovered[0].Port, port)
	}
}
