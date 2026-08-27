package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

var (
	ErrNoIPsAvailable     = errors.New("no virtual overlay IPs available in range")
	ErrIPAlreadyAllocated = errors.New("virtual overlay IP is already allocated")
	ErrInvalidIPRange     = errors.New("IP is outside the permitted allocation range")
	ErrDeviceNotFound     = errors.New("device not found in IPAM registry")
	ErrThreadNotFound     = errors.New("thread not found in IPAM registry")
)

// IPAMManager manages IP allocations for Threads and Devices within the 100.64.0.0/10 overlay range.
type IPAMManager struct {
	mu sync.RWMutex

	cidr     string
	serverIP net.IP

	threadStart uint32
	threadEnd   uint32
	deviceStart uint32
	deviceEnd   uint32

	// Allocations
	hostnameToIP map[string]uint32
	ipToHostname map[uint32]string

	deviceNameToIP map[string]uint32
	ipToDeviceName map[uint32]string

	allocatedIPs map[uint32]bool
}

// NewIPAMManager initializes an IPAM manager with the standard 100.64.0.0/10 overlay range.
func NewIPAMManager(customCIDR ...string) (*IPAMManager, error) {
	cidr := "100.64.0.0/10"
	if len(customCIDR) > 0 && customCIDR[0] != "" {
		cidr = customCIDR[0]
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid overlay CIDR %q: %w", cidr, err)
	}

	baseIP := ipNet.IP.To4()
	if baseIP == nil {
		return nil, fmt.Errorf("overlay CIDR must be IPv4: %s", cidr)
	}

	baseInt := binary.BigEndian.Uint32(baseIP)

	// Server IP: 100.64.0.1
	serverIPInt := baseInt + 1
	serverIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(serverIP, serverIPInt)

	// Thread Range: 100.64.0.2 to 100.64.127.254
	// Devices Range: 100.64.128.1 to 100.64.255.254 (and up to 100.127.255.254 in /10)
	threadStart := baseInt + 2
	threadEnd := baseInt + (128 << 8) - 2

	deviceStart := baseInt + (128 << 8) + 1
	deviceEnd := baseInt + (1 << 22) - 2
	if (baseInt + (256 << 8) - 2) <= deviceEnd {
		deviceEnd = baseInt + (256 << 8) - 2
	}

	allocated := make(map[uint32]bool)
	allocated[serverIPInt] = true

	return &IPAMManager{
		cidr:           cidr,
		serverIP:       serverIP,
		threadStart:    threadStart,
		threadEnd:      threadEnd,
		deviceStart:    deviceStart,
		deviceEnd:      deviceEnd,
		hostnameToIP:   make(map[string]uint32),
		ipToHostname:   make(map[uint32]string),
		deviceNameToIP: make(map[string]uint32),
		ipToDeviceName: make(map[uint32]string),
		allocatedIPs:   allocated,
	}, nil
}

// CIDR returns the configured overlay subnet CIDR string.
func (m *IPAMManager) CIDR() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cidr
}

// ServerIP returns the Fabric Server virtual IP (100.64.0.1).
func (m *IPAMManager) ServerIP() net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(net.IP, len(m.serverIP))
	copy(out, m.serverIP)
	return out
}

// AllocateThreadIP allocates or retrieves a virtual IP for a Thread.
func (m *IPAMManager) AllocateThreadIP(hostname string) (net.IP, error) {
	if hostname == "" {
		return nil, errors.New("hostname cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if ipInt, ok := m.hostnameToIP[hostname]; ok {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipInt)
		return ip, nil
	}

	for candidate := m.threadStart; candidate <= m.threadEnd; candidate++ {
		// Skip broadcast / network addresses in byte 4 (.0 or .255)
		if candidate&0xFF == 0 || candidate&0xFF == 255 {
			continue
		}
		if !m.allocatedIPs[candidate] {
			m.allocatedIPs[candidate] = true
			m.hostnameToIP[hostname] = candidate
			m.ipToHostname[candidate] = hostname

			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, candidate)
			return ip, nil
		}
	}

	return nil, ErrNoIPsAvailable
}

// ReleaseThreadIP releases the virtual IP assigned to a Thread.
func (m *IPAMManager) ReleaseThreadIP(hostname string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ipInt, ok := m.hostnameToIP[hostname]; ok {
		delete(m.hostnameToIP, hostname)
		delete(m.ipToHostname, ipInt)
		delete(m.allocatedIPs, ipInt)
	}
}

// ReserveThreadIP explicitly reserves a specific IP for a thread.
func (m *IPAMManager) ReserveThreadIP(hostname string, ip net.IP) error {
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("invalid IPv4 address: %v", ip)
	}

	ipInt := binary.BigEndian.Uint32(v4)
	if ipInt < m.threadStart || ipInt > m.threadEnd {
		return ErrInvalidIPRange
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if prevHostname, inUse := m.ipToHostname[ipInt]; inUse && prevHostname != hostname {
		return ErrIPAlreadyAllocated
	}

	m.allocatedIPs[ipInt] = true
	m.hostnameToIP[hostname] = ipInt
	m.ipToHostname[ipInt] = hostname
	return nil
}

// AllocateDeviceIP allocates or retrieves a virtual IP for a client device.
func (m *IPAMManager) AllocateDeviceIP(name string) (net.IP, error) {
	if name == "" {
		return nil, errors.New("device name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if ipInt, ok := m.deviceNameToIP[name]; ok {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipInt)
		return ip, nil
	}

	for candidate := m.deviceStart; candidate <= m.deviceEnd; candidate++ {
		if candidate&0xFF == 0 || candidate&0xFF == 255 {
			continue
		}
		if !m.allocatedIPs[candidate] {
			m.allocatedIPs[candidate] = true
			m.deviceNameToIP[name] = candidate
			m.ipToDeviceName[candidate] = name

			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, candidate)
			return ip, nil
		}
	}

	return nil, ErrNoIPsAvailable
}

// ReserveDeviceIP explicitly reserves a specific IP for a persisted device during initialization.
func (m *IPAMManager) ReserveDeviceIP(name string, ip net.IP) error {
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("invalid IPv4 address: %v", ip)
	}

	ipInt := binary.BigEndian.Uint32(v4)
	if ipInt < m.deviceStart || ipInt > m.deviceEnd {
		return ErrInvalidIPRange
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if prevName, inUse := m.ipToDeviceName[ipInt]; inUse && prevName != name {
		return ErrIPAlreadyAllocated
	}

	m.allocatedIPs[ipInt] = true
	m.deviceNameToIP[name] = ipInt
	m.ipToDeviceName[ipInt] = name
	return nil
}

// ReleaseDeviceIP releases the virtual IP assigned to a client device.
func (m *IPAMManager) ReleaseDeviceIP(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ipInt, ok := m.deviceNameToIP[name]; ok {
		delete(m.deviceNameToIP, name)
		delete(m.ipToDeviceName, ipInt)
		delete(m.allocatedIPs, ipInt)
	}
}

// LookupIPByHostname retrieves the virtual IP allocated to a thread hostname.
func (m *IPAMManager) LookupIPByHostname(hostname string) (net.IP, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ipInt, ok := m.hostnameToIP[hostname]
	if !ok {
		return nil, false
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip, true
}

// LookupHostnameByIP retrieves the thread hostname associated with a virtual IP.
func (m *IPAMManager) LookupHostnameByIP(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ipInt := binary.BigEndian.Uint32(v4)
	hostname, ok := m.ipToHostname[ipInt]
	return hostname, ok
}

// LookupDeviceByName retrieves the virtual IP for a paired device.
func (m *IPAMManager) LookupDeviceByName(name string) (net.IP, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ipInt, ok := m.deviceNameToIP[name]
	if !ok {
		return nil, false
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip, true
}

// LookupDeviceByIP retrieves the device name associated with a virtual IP.
func (m *IPAMManager) LookupDeviceByIP(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ipInt := binary.BigEndian.Uint32(v4)
	name, ok := m.ipToDeviceName[ipInt]
	return name, ok
}
