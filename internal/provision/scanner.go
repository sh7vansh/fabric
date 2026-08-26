package provision

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

const MaxScanHosts = 65536 // Safety limit: up to a /16 subnet

// DiscoveredHost represents an active SSH endpoint found on the network.
type DiscoveredHost struct {
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	Banner      string        `json:"banner"`
	CleanBanner string        `json:"clean_banner"`
	Latency     time.Duration `json:"latency_ms"`
	Mode        string        `json:"mode,omitempty"`
}

// ScanOptions configures the concurrent network discovery scan.
type ScanOptions struct {
	Ports       []int
	Concurrency int
	Timeout     time.Duration
}

// DefaultScanOptions returns standard production scan parameters.
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

// GetDefaultLocalCIDR attempts to determine the primary network interface's IPv4 CIDR.
func GetDefaultLocalCIDR() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("could not determine default route: %w", err)
	}
	defer conn.Close()

	localIP := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if localIP == nil {
		return "", fmt.Errorf("detected non-IPv4 local address")
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if ipNet.IP.To4() != nil && ipNet.IP.Equal(localIP) {
						maskSize, _ := ipNet.Mask.Size()
						networkIP := ipNet.IP.Mask(ipNet.Mask)
						return fmt.Sprintf("%s/%d", networkIP.String(), maskSize), nil
					}
				}
			}
		}
	}

	return fmt.Sprintf("%d.%d.%d.0/24", localIP[0], localIP[1], localIP[2]), nil
}

// ParseTargets parses CIDRs, IP ranges, or single/comma-separated IPs and returns a list of target host IPs.
func ParseTargets(input string, defaultCIDR string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		if defaultCIDR == "" {
			return nil, fmt.Errorf("no target specified and no default CIDR provided")
		}
		input = defaultCIDR
	}

	var targets []string
	seen := make(map[string]bool)

	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "/") {
			ips, err := expandCIDR(part)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					targets = append(targets, ip)
				}
			}
		} else if strings.Contains(part, "-") && isIPRange(part) {
			ips, err := expandIPRange(part)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					targets = append(targets, ip)
				}
			}
		} else {
			ip := net.ParseIP(part)
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					part = ip4.String()
				}
			}
			if !seen[part] {
				seen[part] = true
				targets = append(targets, part)
			}
		}

		if len(targets) > MaxScanHosts {
			return nil, fmt.Errorf("target range exceeds safety limit of %d hosts (%d requested)", MaxScanHosts, len(targets))
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid target hosts found in %q", input)
	}

	return targets, nil
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

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				host, err := ProbeSSH(job.ip, job.port, opts.Timeout)
				if err == nil && host != nil {
					results <- *host
					if onFound != nil {
						onFound(*host)
					}
				}
			}
		}()
	}

	go func() {
		for _, target := range targets {
			for _, port := range opts.Ports {
				jobs <- scanJob{ip: target, port: port}
			}
		}
		close(jobs)
	}()

	wg.Wait()
	close(results)

	var discovered []DiscoveredHost
	for res := range results {
		discovered = append(discovered, res)
	}

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

// ProbeSSH performs a TCP connection and verifies the RFC 4253 SSH server identification string.
func ProbeSSH(ip string, port int, timeout time.Duration) (*DiscoveredHost, error) {
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
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		rawBanner := strings.TrimSpace(line)
		if rawBanner == "" {
			continue
		}

		if strings.HasPrefix(rawBanner, "SSH-") {
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

		if strings.HasPrefix(rawBanner, "HTTP/") || strings.HasPrefix(rawBanner, "<html") {
			return nil, fmt.Errorf("non-SSH HTTP service on %s: %q", addr, rawBanner)
		}
	}

	return nil, fmt.Errorf("no valid SSH banner received from %s", addr)
}

func isIPRange(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	return startIP != nil && startIP.To4() != nil
}

func expandIPRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range %q", rangeStr)
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startStr).To4()
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP in range %q", rangeStr)
	}

	var endIP net.IP
	if strings.Contains(endStr, ".") {
		endIP = net.ParseIP(endStr).To4()
		if endIP == nil {
			return nil, fmt.Errorf("invalid end IP in range %q", rangeStr)
		}
	} else {
		octet, err := strconv.Atoi(endStr)
		if err != nil || octet < 0 || octet > 255 {
			return nil, fmt.Errorf("invalid end octet in range %q: %s", rangeStr, endStr)
		}
		endIP = net.IPv4(startIP[0], startIP[1], startIP[2], byte(octet)).To4()
	}

	if bytes.Compare(startIP, endIP) > 0 {
		return nil, fmt.Errorf("start IP %s is greater than end IP %s", startIP, endIP)
	}

	var ips []string
	curr := make(net.IP, 4)
	copy(curr, startIP)

	for {
		ips = append(ips, curr.String())
		if len(ips) > MaxScanHosts {
			return nil, fmt.Errorf("IP range %q exceeds safety limit of %d hosts", rangeStr, MaxScanHosts)
		}
		if curr.Equal(endIP) {
			break
		}
		incrementIP(curr)
	}

	return ips, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IPv6 scanning is not supported in CIDR mode (%s)", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	totalHosts := 1 << (bits - ones)

	if totalHosts > MaxScanHosts {
		return nil, fmt.Errorf("subnet /%d is too large (%d hosts, max %d allowed)", ones, totalHosts, MaxScanHosts)
	}

	var ips []string
	curr := make(net.IP, len(ipNet.IP))
	copy(curr, ipNet.IP)

	for ipNet.Contains(curr) {
		if ones <= 30 {
			if !isNetworkOrBroadcast(curr, ipNet) {
				ips = append(ips, curr.String())
			}
		} else {
			ips = append(ips, curr.String())
		}
		incrementIP(curr)
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	netIP := ipNet.IP.To4()
	if ip4.Equal(netIP) {
		return true
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = netIP[i] | ^ipNet.Mask[i]
	}

	return ip4.Equal(broadcast)
}
