package main

import (
	"encoding/base64"
	"strings"

	"fabric/internal/protocol"

	"github.com/miekg/dns"
)

// ProcessDNSQuery takes a base64-encoded RFC 1035 wire format query from a node,
// resolves it against the in-memory node map, and returns a DNSResponse.
func ProcessDNSQuery(req protocol.DNSQuery, domain string, proxyIP string) protocol.DNSResponse {
	resp := protocol.DNSResponse{
		Type:      protocol.TypeDNSResponse,
		SessionID: req.SessionID,
	}

	queryWire, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		resp.RCode = dns.RcodeServerFailure
		return resp
	}

	m := new(dns.Msg)
	if err := m.Unpack(queryWire); err != nil {
		resp.RCode = dns.RcodeFormatError
		return resp
	}

	reply := new(dns.Msg)
	reply.SetReply(m)
	reply.Authoritative = true

	domainSuffix := "." + domain + "."

	for _, q := range m.Question {
		name := strings.ToLower(q.Name)

		if !strings.HasSuffix(name, domainSuffix) {
			reply.Rcode = dns.RcodeNameError
			continue
		}

		// Extract node ID by stripping the domain suffix
		// Example: node-1.fabric.mesh. -> node-1
		prefix := strings.TrimSuffix(name, domainSuffix)
		
		// Handle wildcards: e.g. api.node-1
		parts := strings.Split(prefix, ".")
		nodeID := parts[len(parts)-1] // The node ID is the right-most part of the prefix

		nodesLock.RLock()
		_, isOnline := nodes[nodeID]
		nodesLock.RUnlock()

		if isOnline && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
			rr, err := dns.NewRR(q.Name + " 10 IN A " + proxyIP)
			if err == nil {
				reply.Answer = append(reply.Answer, rr)
			}
		} else if isOnline {
			// Online, but not an A record request
			// We only synthesize A records for now.
		} else {
			reply.Rcode = dns.RcodeNameError
		}
	}

	if len(reply.Answer) > 0 {
		reply.Rcode = dns.RcodeSuccess
	} else if reply.Rcode == dns.RcodeSuccess {
		// If we didn't add answers and didn't set NXDOMAIN, it's NOERROR with 0 answers.
	}

	wire, err := reply.Pack()
	if err == nil {
		resp.Data = base64.StdEncoding.EncodeToString(wire)
	}
	resp.RCode = reply.Rcode
	if reply.Rcode == dns.RcodeNameError {
		resp.TTL = 5 // Negative cache TTL
	} else {
		resp.TTL = 10 // Positive cache TTL
	}

	return resp
}
