package wireguard

import (
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// DNSServer provides an in-memory RFC 1035 DNS server attached directly to the userspace netstack.
type DNSServer struct {
	server     *dns.Server
	packetConn net.PacketConn
	ipam       *IPAMManager
	meshDomain string
	mu         sync.RWMutex
	closed     bool
}

// NewDNSServer creates and starts an in-memory DNS server listening on the provided virtual PacketConn.
func NewDNSServer(packetConn net.PacketConn, ipam *IPAMManager, meshDomain string) (*DNSServer, error) {
	if meshDomain == "" {
		meshDomain = "fabric.mesh"
	}
	meshDomain = strings.TrimPrefix(meshDomain, ".")

	s := &DNSServer{
		packetConn: packetConn,
		ipam:       ipam,
		meshDomain: strings.ToLower(meshDomain),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	s.server = &dns.Server{
		PacketConn: packetConn,
		Handler:    mux,
	}

	go func() {
		if err := s.server.ActivateAndServe(); err != nil && !s.isClosed() {
			log.Printf("[WireGuard/DNS] In-memory DNS server error: %v\n", err)
		}
	}()

	return s, nil
}

func (s *DNSServer) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// Close gracefully stops the in-memory DNS server and closes the underlying virtual packet connection.
func (s *DNSServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	var err error
	if s.server != nil {
		err = s.server.Shutdown()
	}
	if s.packetConn != nil {
		_ = s.packetConn.Close()
	}
	return err
}

func (s *DNSServer) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	for _, q := range r.Question {
		name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		matchedDomain := false
		suffix := ""

		for _, candidate := range []string{s.meshDomain, "fabric", "fabric.mesh", "mesh"} {
			if name == candidate {
				matchedDomain = true
				suffix = candidate
				break
			}
			if strings.HasSuffix(name, "."+candidate) {
				matchedDomain = true
				suffix = candidate
				break
			}
		}

		if !matchedDomain {
			// Non-mesh query -> NameError
			m.Rcode = dns.RcodeNameError
			continue
		}

		// Extract target hostname prefix
		prefix := strings.TrimSuffix(name, "."+suffix)
		if prefix == suffix {
			prefix = ""
		}

		// Handle server/gateway root domain queries: fabric, server.fabric, gateway.fabric
		if prefix == "" || prefix == "server" || prefix == "gateway" {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    10,
					},
					A: s.ipam.ServerIP().To4(),
				})
			}
			continue
		}

		// Look up thread in IPAM
		parts := strings.Split(prefix, ".")
		targetHost := parts[0]

		ip, ok := s.ipam.LookupIPByHostname(targetHost)
		if !ok {
			// Check if device name
			if devIP, devOk := s.ipam.LookupDeviceByName(targetHost); devOk {
				ip = devIP
				ok = true
			}
		}

		if !ok {
			m.Rcode = dns.RcodeNameError
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    10,
				},
				A: ip.To4(),
			})
		case dns.TypeAAAA:
			// No AAAA records for IPv4 overlay
			m.Rcode = dns.RcodeSuccess
		default:
			m.Rcode = dns.RcodeSuccess
		}
	}

	_ = w.WriteMsg(m)
}
