package meshdns

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fabric/internal/protocol"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

type Resolver struct {
	domain   string
	wsConn   *websocket.Conn
	pending  map[string]chan protocol.DNSResponse
	pendMux  sync.Mutex
	server   *dns.Server
}

func NewResolver(domain string) *Resolver {
	return &Resolver{
		domain:  domain,
		pending: make(map[string]chan protocol.DNSResponse),
	}
}

func (r *Resolver) SetConnection(conn *websocket.Conn) {
	r.wsConn = conn
}

func (r *Resolver) HandleDNSResponse(resp protocol.DNSResponse) {
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

	if r.wsConn != nil {
		query := protocol.DNSQuery{
			Type:      protocol.TypeDNSQuery,
			SessionID: sessionID,
			Name:      name,
			QType:     q.Qtype,
			Data:      base64.StdEncoding.EncodeToString(reqWire),
		}
		r.wsConn.WriteJSON(query)
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

// SyncHostsFile pulls nodes from the Socket REST API and writes them to /etc/hosts
// if systemd-resolved is not available.
func SyncHostsFile(apiURL, token, domain, socketURL string) {
	if HasSystemdResolved() {
		return
	}

	req, err := http.NewRequest("GET", apiURL+"/nodes", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	var nodes []protocol.NodeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return
	}

	UpdateHostsBlock(nodes, domain, socketURL)
}
