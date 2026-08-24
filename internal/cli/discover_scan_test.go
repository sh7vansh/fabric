package cli

import (
	"fmt"
	"net"
	"strconv"
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
				// Keep connection open briefly to let client read
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
	// 1. Valid OpenSSH server
	sshLn, sshPort := startMockSSHServer(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2")
	defer sshLn.Close()

	// 2. Non-SSH HTTP server
	httpLn, httpPort := startMockHTTPServer(t)
	defer httpLn.Close()

	// 3. Pre-banner text followed by SSH identification (RFC 4253 § 4.2)
	preLn, prePort := startMockSSHServer(t, "Authorized uses only\r\nSSH-2.0-OpenSSH_9.0")
	defer preLn.Close()

	// Test valid SSH
	host, err := probeSSH("127.0.0.1", sshPort, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("probeSSH valid failed: %v", err)
	}
	if host.Port != sshPort {
		t.Errorf("Port = %d, want %d", host.Port, sshPort)
	}
	if host.CleanBanner != "OpenSSH_9.2p1 Debian-2" {
		t.Errorf("CleanBanner = %q, want %q", host.CleanBanner, "OpenSSH_9.2p1 Debian-2")
	}

	// Test pre-banner SSH
	hostPre, err := probeSSH("127.0.0.1", prePort, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("probeSSH pre-banner failed: %v", err)
	}
	if hostPre.CleanBanner != "OpenSSH_9.0" {
		t.Errorf("CleanBanner = %q, want %q", hostPre.CleanBanner, "OpenSSH_9.0")
	}

	// Test non-SSH rejection
	_, err = probeSSH("127.0.0.1", httpPort, 500*time.Millisecond)
	if err == nil {
		t.Errorf("probeSSH on HTTP port should have failed, but succeeded")
	}

	// Test non-existent closed port
	_, err = probeSSH("127.0.0.1", 59999, 100*time.Millisecond)
	if err == nil {
		t.Errorf("probeSSH on closed port should have failed, but succeeded")
	}
}

func TestScanTargetsConcurrent(t *testing.T) {
	sshLn1, port1 := startMockSSHServer(t, "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
	defer sshLn1.Close()

	sshLn2, port2 := startMockSSHServer(t, "SSH-2.0-Dropbear_2020.81")
	defer sshLn2.Close()

	httpLn, httpPort := startMockHTTPServer(t)
	defer httpLn.Close()

	targets := []string{"127.0.0.1"}
	opts := ScanOptions{
		Ports:       []int{port1, port2, httpPort, 59998},
		Concurrency: 10,
		Timeout:     300 * time.Millisecond,
	}

	var foundCount int
	discovered, err := ScanTargets(targets, opts, func(h DiscoveredHost) {
		foundCount++
	})
	if err != nil {
		t.Fatalf("ScanTargets failed: %v", err)
	}

	if len(discovered) != 2 {
		t.Fatalf("Expected 2 discovered SSH hosts, got %d: %+v", len(discovered), discovered)
	}

	if foundCount != 2 {
		t.Errorf("Callback count = %d, want 2", foundCount)
	}

	expectedPorts := map[int]string{
		port1: "OpenSSH_8.9p1 Ubuntu",
		port2: "Dropbear_2020.81",
	}

	for _, d := range discovered {
		wantBanner, ok := expectedPorts[d.Port]
		if !ok {
			t.Errorf("Unexpected discovered port: %d", d.Port)
		}
		if d.CleanBanner != wantBanner {
			t.Errorf("Port %d CleanBanner = %q, want %q", d.Port, d.CleanBanner, wantBanner)
		}
	}
}

func TestScanTargetsSorting(t *testing.T) {
	sshLn, port := startMockSSHServer(t, "SSH-2.0-OpenSSH_Test")
	defer sshLn.Close()

	targets := []string{"127.0.0.3", "127.0.0.1", "127.0.0.2"}
	opts := ScanOptions{
		Ports:       []int{port},
		Concurrency: 5,
		Timeout:     200 * time.Millisecond,
	}

	discovered, err := ScanTargets(targets, opts, nil)
	if err != nil {
		t.Fatalf("ScanTargets failed: %v", err)
	}

	for i, d := range discovered {
		wantIP := "127.0.0." + strconv.Itoa(i+1)
		if d.IP != wantIP {
			t.Errorf("Result [%d] IP = %s; want %s", i, d.IP, wantIP)
		}
	}
}
