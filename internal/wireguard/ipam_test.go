package wireguard

import (
	"net"
	"testing"
)

func TestIPAMManagerThreadAllocation(t *testing.T) {
	ipam, err := NewIPAMManager()
	if err != nil {
		t.Fatalf("failed to create IPAMManager: %v", err)
	}

	if ipam.ServerIP().String() != "100.64.0.1" {
		t.Fatalf("expected server IP 100.64.0.1, got %s", ipam.ServerIP())
	}

	ip1, err := ipam.AllocateThreadIP("worker-1")
	if err != nil {
		t.Fatalf("failed to allocate IP for worker-1: %v", err)
	}
	if ip1.String() != "100.64.0.2" {
		t.Errorf("expected 100.64.0.2, got %s", ip1)
	}

	// Idempotent allocation
	ip1Repeat, err := ipam.AllocateThreadIP("worker-1")
	if err != nil || !ip1Repeat.Equal(ip1) {
		t.Errorf("expected same IP for worker-1, got %s", ip1Repeat)
	}

	ip2, err := ipam.AllocateThreadIP("worker-2")
	if err != nil {
		t.Fatalf("failed to allocate IP for worker-2: %v", err)
	}
	if ip2.String() != "100.64.0.3" {
		t.Errorf("expected 100.64.0.3, got %s", ip2)
	}

	// Lookups
	ip, ok := ipam.LookupIPByHostname("worker-1")
	if !ok || !ip.Equal(ip1) {
		t.Errorf("lookup by hostname failed: got %v, ok %v", ip, ok)
	}

	host, ok := ipam.LookupHostnameByIP(ip2)
	if !ok || host != "worker-2" {
		t.Errorf("lookup by IP failed: got %q, ok %v", host, ok)
	}

	// Release
	ipam.ReleaseThreadIP("worker-1")
	_, ok = ipam.LookupIPByHostname("worker-1")
	if ok {
		t.Errorf("expected worker-1 to be released")
	}

	// Reallocation of released IP
	ipNew, err := ipam.AllocateThreadIP("worker-3")
	if err != nil || !ipNew.Equal(ip1) {
		t.Errorf("expected reallocated IP %s, got %s", ip1, ipNew)
	}
}

func TestIPAMManagerDeviceAllocation(t *testing.T) {
	ipam, err := NewIPAMManager()
	if err != nil {
		t.Fatalf("failed to create IPAMManager: %v", err)
	}

	devIP1, err := ipam.AllocateDeviceIP("iphone")
	if err != nil {
		t.Fatalf("failed to allocate IP for device iphone: %v", err)
	}
	if devIP1.String() != "100.64.128.1" {
		t.Errorf("expected device start IP 100.64.128.1, got %s", devIP1)
	}

	// Reserve explicit IP
	customIP := net.ParseIP("100.64.128.50")
	if err := ipam.ReserveDeviceIP("ipad", customIP); err != nil {
		t.Fatalf("failed to reserve device IP: %v", err)
	}

	// Duplicate reservation error
	if err := ipam.ReserveDeviceIP("other", customIP); err != ErrIPAlreadyAllocated {
		t.Errorf("expected ErrIPAlreadyAllocated, got %v", err)
	}

	// Invalid range
	outOfRange := net.ParseIP("100.64.0.5")
	if err := ipam.ReserveDeviceIP("tv", outOfRange); err != ErrInvalidIPRange {
		t.Errorf("expected ErrInvalidIPRange, got %v", err)
	}

	// Device lookups
	ip, ok := ipam.LookupDeviceByName("ipad")
	if !ok || !ip.Equal(customIP) {
		t.Errorf("device lookup by name failed: got %v, ok %v", ip, ok)
	}

	name, ok := ipam.LookupDeviceByIP(customIP)
	if !ok || name != "ipad" {
		t.Errorf("device lookup by IP failed: got %q, ok %v", name, ok)
	}

	// Release
	ipam.ReleaseDeviceIP("iphone")
	_, ok = ipam.LookupDeviceByName("iphone")
	if ok {
		t.Errorf("expected iphone to be released")
	}
}
