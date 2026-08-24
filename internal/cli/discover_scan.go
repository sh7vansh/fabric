package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiscoveredHost represents an active SSH endpoint found on the network.
type DiscoveredHost struct {
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	Banner      string        `json:"banner"`
	CleanBanner string        `json:"clean_banner"`
	Latency     time.Duration `json:"latency_ms"`
}

// ScanOptions configures the concurrent network discovery scan.
type ScanOptions struct {
	Ports       []int
	Concurrency int
	Timeout     time.Duration
}

// DefaultScanOptions returns the standard production scan parameters.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Ports:       []int{22},
		Concurrency: 128,
		Timeout:     1000 * time.Millisecond,
	}
}

type scanJob struct {
	ip   string
	port int
}

// ScanTargets scans a list of IP targets concurrently across the specified ports.
func ScanTargets(targets []string, opts ScanOptions, onFound func(DiscoveredHost)) ([]DiscoveredHost, error) {
	if len(opts.Ports) == 0 {
		opts.Ports = []int{22}
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 128
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1000 * time.Millisecond
	}

	jobs := make(chan scanJob, opts.Concurrency*2)
	results := make(chan DiscoveredHost, len(targets)*len(opts.Ports))

	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				host, err := probeSSH(job.ip, job.port, opts.Timeout)
				if err == nil && host != nil {
					results <- *host
					if onFound != nil {
						onFound(*host)
					}
				}
			}
		}()
	}

	// Feed jobs into channel in a separate goroutine
	go func() {
		for _, target := range targets {
			for _, port := range opts.Ports {
				jobs <- scanJob{ip: target, port: port}
			}
		}
		close(jobs)
	}()

	// Wait for all workers and close results channel
	wg.Wait()
	close(results)

	var discovered []DiscoveredHost
	for res := range results {
		discovered = append(discovered, res)
	}

	// Sort results deterministically by IP and Port
	sort.Slice(discovered, func(i, j int) bool {
		ipI := net.ParseIP(discovered[i].IP).To4()
		ipJ := net.ParseIP(discovered[j].IP).To4()
		if ipI != nil && ipJ != nil && !ipI.Equal(ipJ) {
			return bytes.Compare(ipI, ipJ) < 0
		}
		if discovered[i].IP != discovered[j].IP {
			return discovered[i].IP < discovered[j].IP
		}
		return discovered[i].Port < discovered[j].Port
	})

	return discovered, nil
}

// probeSSH performs a TCP connection and verifies the RFC 4253 SSH server identification string.
func probeSSH(ip string, port int, timeout time.Duration) (*DiscoveredHost, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	latency := time.Since(start)

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	rawBanner := strings.TrimSpace(line)

	// RFC 4253 Section 4.2: Server MUST identify itself with "SSH-protoversion-softwareversion..."
	if !strings.HasPrefix(rawBanner, "SSH-") {
		return nil, fmt.Errorf("non-SSH service on %s: %q", addr, rawBanner)
	}

	clean := rawBanner
	if strings.HasPrefix(clean, "SSH-2.0-") {
		clean = strings.TrimPrefix(clean, "SSH-2.0-")
	} else if strings.HasPrefix(clean, "SSH-1.99-") {
		clean = strings.TrimPrefix(clean, "SSH-1.99-")
	}

	return &DiscoveredHost{
		IP:          ip,
		Port:        port,
		Banner:      rawBanner,
		CleanBanner: clean,
		Latency:     latency.Round(time.Millisecond),
	}, nil
}
