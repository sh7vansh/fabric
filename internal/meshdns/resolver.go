package meshdns

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fabric/internal/protocol"

	"github.com/google/uuid"
	"github.com/miekg/dns"
)

type Resolver struct {
	domain   string
	mux      *protocol.StreamMultiplexer
	cache    map[string]protocol.DNSResponse
	cacheMux sync.RWMutex
	pending  map[string]chan protocol.DNSResponse
	pendMux  sync.Mutex
	server   *dns.Server
}

func NewResolver(domain string) *Resolver {
	return &Resolver{
		domain:  domain,
		cache:   make(map[string]protocol.DNSResponse),
		pending: make(map[string]chan protocol.DNSResponse),
	}
}

func (r *Resolver) SetMultiplexer(mux *protocol.StreamMultiplexer) {
	r.mux = mux
}

func (r *Resolver) HandleDNSResponse(resp protocol.DNSResponse) {
	if resp.RCode == dns.RcodeSuccess && resp.TTL > 0 {
		replyWire, err := base64.StdEncoding.DecodeString(resp.Data)
		if err == nil {
			reply := new(dns.Msg)
			if err := reply.Unpack(replyWire); err == nil && len(reply.Question) > 0 {
				name := strings.ToLower(reply.Question[0].Name)
				r.cacheMux.Lock()
				r.cache[name] = resp
				r.cacheMux.Unlock()

				time.AfterFunc(time.Duration(resp.TTL)*time.Second, func() {
					r.cacheMux.Lock()
					delete(r.cache, name)
					r.cacheMux.Unlock()
				})
			}
		}
	}

	r.pendMux.Lock()
	ch, ok := r.pending[resp.SessionID]
	if ok {
		delete(r.pending, resp.SessionID)
	}
	r.pendMux.Unlock()

	if ok {
		ch <- resp
	}
}

func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	name := strings.ToLower(q.Name)

	if !strings.HasSuffix(name, "."+r.domain+".") {
		dns.HandleFailed(w, req)
		return
	}

	r.cacheMux.RLock()
	cachedResp, found := r.cache[name]
	r.cacheMux.RUnlock()

	if found {
		replyWire, err := base64.StdEncoding.DecodeString(cachedResp.Data)
		if err == nil {
			reply := new(dns.Msg)
			if err := reply.Unpack(replyWire); err == nil {
				reply.Id = req.Id
				w.WriteMsg(reply)
				return
			}
		}
	}

	reqWire, err := req.Pack()
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	sessionID := uuid.New().String()
	ch := make(chan protocol.DNSResponse, 1)

	r.pendMux.Lock()
	r.pending[sessionID] = ch
	r.pendMux.Unlock()

	if r.mux != nil {
		query := protocol.DNSQuery{
			Type:      protocol.TypeDNSQuery,
			SessionID: sessionID,
			Name:      name,
			QType:     q.Qtype,
			Data:      base64.StdEncoding.EncodeToString(reqWire),
		}
		
		go func() {
			stream, err := r.mux.Session.Open()
			if err == nil {
				b, _ := json.Marshal(query)
				stream.Write(b)
				stream.Close()
			}
		}()
	} else {
		dns.HandleFailed(w, req)
		return
	}

	select {
	case resp := <-ch:
		replyWire, err := base64.StdEncoding.DecodeString(resp.Data)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		
		reply := new(dns.Msg)
		if err := reply.Unpack(replyWire); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		
		reply.Id = req.Id
		w.WriteMsg(reply)
	case <-time.After(5 * time.Second):
		r.pendMux.Lock()
		delete(r.pending, sessionID)
		r.pendMux.Unlock()
		dns.HandleFailed(w, req)
	}
}

func (r *Resolver) Start() error {
	r.server = &dns.Server{Addr: "127.0.0.1:53535", Net: "udp", Handler: r}
	go func() {
		if err := r.server.ListenAndServe(); err != nil {
			log.Printf("Failed to setup local DNS server: %v\n", err)
		}
	}()
	return nil
}

func (r *Resolver) Stop() {
	if r.server != nil {
		r.server.Shutdown()
	}
}

func HasSystemdResolved() bool {
	_, err := os.Stat("/run/systemd/resolve/stub-resolv.conf")
	return err == nil
}

func ConfigureOS(domain string) error {
	if HasSystemdResolved() {
		// Clean up any old state first
		exec.Command("resolvectl", "revert", "lo").Run()

		cmd := exec.Command("resolvectl", "domain", "lo", "~"+domain)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("resolvectl domain failed: %v", err)
		}

		cmd = exec.Command("resolvectl", "dns", "lo", "127.0.0.1:53535")
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: resolvectl dns lo 127.0.0.1:53535 failed: %v", err)
		}

		cmd = exec.Command("resolvectl", "default-route", "lo", "false")
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: resolvectl default-route failed: %v", err)
		}

		return nil
	}
	return nil
}

func RevertOS() {
	if HasSystemdResolved() {
		exec.Command("resolvectl", "revert", "lo").Run()
	}
}
