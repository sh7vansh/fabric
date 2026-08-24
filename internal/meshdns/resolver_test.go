package meshdns

import (
	"encoding/base64"
	"fabric/internal/protocol"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestLocalStubResolver(t *testing.T) {
	r := NewResolver("fabric.mesh")
	if err := r.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer r.Stop()
	time.Sleep(100 * time.Millisecond) // Wait for server to start

	// Send query
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("test.fabric.mesh.", dns.TypeA)
	
	// We run the query in a goroutine because it will block (no socket connected)
	go func() {
		// Expect failure since no websocket is connected
		c.Exchange(m, "127.0.0.1:53535")
	}()

	time.Sleep(50 * time.Millisecond)
	
	r.pendMux.Lock()
	if len(r.pending) == 0 {
		t.Errorf("Expected query to be pending")
	}
	// simulate response
	for id, ch := range r.pending {
		respMsg := new(dns.Msg)
		respMsg.SetReply(m)
		rr, _ := dns.NewRR("test.fabric.mesh. 10 IN A 192.168.1.1")
		respMsg.Answer = append(respMsg.Answer, rr)
		wire, _ := respMsg.Pack()

		ch <- protocol.DNSResponse{
			Type:      protocol.TypeDNSResponse,
			SessionID: id,
			RCode:     dns.RcodeSuccess,
			TTL:       10,
			Data:      base64.StdEncoding.EncodeToString(wire),
		}
	}
	r.pendMux.Unlock()

	// Testing cache logic directly since HandleDNSResponse does the caching
	respMsg := new(dns.Msg)
	respMsg.SetReply(m)
	rr, _ := dns.NewRR("test.fabric.mesh. 10 IN A 192.168.1.1")
	respMsg.Answer = append(respMsg.Answer, rr)
	wire, _ := respMsg.Pack()
	
	r.HandleDNSResponse(protocol.DNSResponse{
		Type:      protocol.TypeDNSResponse,
		SessionID: "fake",
		RCode:     dns.RcodeSuccess,
		TTL:       10,
		Data:      base64.StdEncoding.EncodeToString(wire),
	})

	r.cacheMux.RLock()
	_, found := r.cache["test.fabric.mesh."]
	r.cacheMux.RUnlock()
	if !found {
		t.Errorf("Expected response to be cached")
	}
}
