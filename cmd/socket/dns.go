package main

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

// StartDNSServer starts a simple DNS server on UDP port 53.
// It resolves the given domain (and its subdomains) to the Socket's own IP address,
// forcing traffic to hit our reverse proxy.
func StartDNSServer(socketIP string, domain string) {
	dns.HandleFunc(domain+".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			if q.Qtype == dns.TypeA && strings.HasSuffix(q.Name, "."+domain+".") {
				rr, err := dns.NewRR(q.Name + " 60 IN A " + socketIP)
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		w.WriteMsg(m)
	})

	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Starting DNS server on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %s", err.Error())
	}
}
