package cli

import (
	"fmt"
	"net"
	"strings"
)

const MaxScanHosts = 65536 // Safety limit: up to a /16 subnet

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

	// Look for the interface matching this IP to extract the subnet mask
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
						// Return the network CIDR string, e.g. 192.168.1.0/24
						maskSize, _ := ipNet.Mask.Size()
						networkIP := ipNet.IP.Mask(ipNet.Mask)
						return fmt.Sprintf("%s/%d", networkIP.String(), maskSize), nil
					}
				}
			}
		}
	}

	// Fallback to /24 on the local IP's subnet
	return fmt.Sprintf("%d.%d.%d.0/24", localIP[0], localIP[1], localIP[2]), nil
}

// ParseTargets parses CIDRs, IP ranges, or single/comma-separated IPs and returns a list of target host IPs.
func ParseTargets(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		defaultCIDR, err := GetDefaultLocalCIDR()
		if err != nil {
			return nil, fmt.Errorf("no target specified and failed to auto-detect local subnet: %w", err)
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
			// CIDR block
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
		} else {
			// Single IP or Hostname
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

// expandCIDR generates all usable host IP addresses within an IPv4 CIDR range.
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
		// For /31 and /32, keep all addresses. For standard subnets (<= /30), skip network and broadcast.
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
		return true // Network address (.0)
	}

	// Calculate broadcast address: netIP | ^mask
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = netIP[i] | ^ipNet.Mask[i]
	}

	return ip4.Equal(broadcast)
}
