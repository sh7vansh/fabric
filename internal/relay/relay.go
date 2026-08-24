package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fabric/internal/protocol"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

// NodeSession wraps a connected node's multiplexer session and telemetry metadata.
type NodeSession struct {
	Mux      *protocol.StreamMultiplexer
	Metadata protocol.NodeMetadata
}

// Config configures the MeshRelay control-plane.
type Config struct {
	Domain   string
	Token    string
	PingFreq time.Duration
}

// Relay is the deep control-plane module managing mesh node registration,
// session displacement, multiplexed stream routing, DNS wire resolution, and synchronization.
type Relay struct {
	domain   string
	token    string
	nodes    map[string]*NodeSession
	mu       sync.RWMutex
	closeCh  chan struct{}
	closed   bool
	closeMux sync.Mutex
}

// New creates and initializes a new MeshRelay instance.
func New(cfg Config) *Relay {
	domain := cfg.Domain
	if domain == "" {
		domain = "fabric.mesh"
	}

	r := &Relay{
		domain:  domain,
		token:   cfg.Token,
		nodes:   make(map[string]*NodeSession),
		closeCh: make(chan struct{}),
	}

	pingFreq := cfg.PingFreq
	if pingFreq > 0 {
		go r.pingLoop(pingFreq)
	}

	return r
}

// CheckOrigin validates the incoming WebSocket request Origin header.
func (r *Relay) CheckOrigin(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		// Non-browser direct CLI or agent client
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	originHost := strings.ToLower(u.Hostname())
	if originHost == "localhost" || originHost == "127.0.0.1" || originHost == "::1" {
		return true
	}

	reqHost := req.Host
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	if strings.EqualFold(originHost, reqHost) {
		return true
	}

	domain := strings.ToLower(r.domain)
	if domain != "" {
		if originHost == domain || strings.HasSuffix(originHost, "."+domain) {
			return true
		}
	}

	return false
}

// Upgrader returns a websocket.Upgrader configured with the relay origin check policy.
func (r *Relay) Upgrader() websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(req *http.Request) bool {
			return r.CheckOrigin(req)
		},
	}
}

// ServeWS upgrades and serves a WebSocket connection, managing the entire multiplexed session lifecycle.
func (r *Relay) ServeWS(conn *websocket.Conn, remoteAddr string) error {
	return r.ServeWSAuth(conn, remoteAddr, false)
}

// ServeWSAuth upgrades and serves a WebSocket connection with explicit pre-authentication state.
func (r *Relay) ServeWSAuth(conn *websocket.Conn, remoteAddr string, authenticated bool) error {
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, true)
	if err != nil {
		return err
	}

	proxyIP := "127.0.0.1"
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		proxyIP = tcpAddr.IP.String()
	}

	return r.ServeMuxAuth(mux, remoteAddr, proxyIP, authenticated)
}

// ServeMux manages an incoming stream multiplexer, routing handshakes, DNS queries, and execution streams.
func (r *Relay) ServeMux(mux *protocol.StreamMultiplexer, remoteAddr, proxyIP string) error {
	return r.ServeMuxAuth(mux, remoteAddr, proxyIP, false)
}

// ServeMuxAuth manages an incoming stream multiplexer with session-level authentication gating.
func (r *Relay) ServeMuxAuth(mux *protocol.StreamMultiplexer, remoteAddr, proxyIP string, preAuthenticated bool) error {
	if proxyIP == "" {
		proxyIP = "127.0.0.1"
	}

	var sessionAuthMu sync.RWMutex
	isAuthenticated := preAuthenticated

	router := protocol.NewRouter(mux.Session)

	router.HandleFunc(string(protocol.TypeHandshake), func(stream net.Conn, env []byte) {
		defer stream.Close()
		var hs protocol.Handshake
		if err := json.Unmarshal(env, &hs); err != nil {
			mux.Session.Close()
			return
		}

		if !r.ValidateToken(hs.Token) {
			log.Println("[Relay] Unauthorized connection attempt from:", hs.Hostname)
			mux.Session.Close()
			return
		}

		if hs.Hostname == "" {
			log.Println("[Relay] Handshake rejected: empty hostname")
			mux.Session.Close()
			return
		}

		sessID := hs.SessionID
		if sessID == "" {
			sessID = fmt.Sprintf("sess-%s-%d", hs.Hostname, time.Now().UnixNano())
		}

		meta := protocol.NodeMetadata{
			ID:          hs.Hostname,
			SessionID:   sessID,
			Hostname:    hs.Hostname,
			Domain:      hs.Domain,
			OS:          hs.OS,
			Arch:        hs.Arch,
			Version:     hs.Version,
			RemoteIP:    remoteAddr,
			Status:      "online",
			ConnectedAt: time.Now().UTC().Format(time.RFC3339),
			Tags:        hs.Tags,
		}

		if _, err := r.RegisterNode(meta, mux); err != nil {
			mux.Session.Close()
			return
		}

		sessionAuthMu.Lock()
		isAuthenticated = true
		sessionAuthMu.Unlock()

		log.Printf("[Relay] Node connected successfully: %s (session: %s)\n", hs.Hostname, sessID)
	})

	router.HandleFunc(string(protocol.TypeDNSQuery), func(stream net.Conn, env []byte) {
		sessionAuthMu.RLock()
		authed := isAuthenticated
		sessionAuthMu.RUnlock()

		if !authed {
			log.Println("[Relay] Dropping DNS query on unauthenticated session")
			stream.Close()
			mux.Session.Close()
			return
		}

		defer stream.Close()
		var query protocol.DNSQuery
		if err := json.Unmarshal(env, &query); err != nil {
			return
		}

		resp := r.ResolveDNS(query, proxyIP)
		b, _ := json.Marshal(resp)

		outStream, err := mux.Session.Open()
		if err == nil {
			outStream.Write(b)
			outStream.Close()
		}
	})

	router.HandleFunc(string(protocol.TypeExecRequest), func(stream net.Conn, env []byte) {
		sessionAuthMu.RLock()
		authed := isAuthenticated
		sessionAuthMu.RUnlock()

		if !authed {
			log.Println("[Relay] Dropping ExecRequest on unauthenticated session")
			stream.Close()
			mux.Session.Close()
			return
		}

		var req protocol.ExecRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}
		log.Printf("[Relay] Exec request targeting %s: %s\n", req.TargetHostname, req.Command)
		if err := r.RouteStream(req.TargetHostname, env, stream); err != nil {
			log.Println("[Relay] RouteStream error:", err)
		}
	})

	router.HandleFunc(string(protocol.TypeCopyRequest), func(stream net.Conn, env []byte) {
		sessionAuthMu.RLock()
		authed := isAuthenticated
		sessionAuthMu.RUnlock()

		if !authed {
			log.Println("[Relay] Dropping CopyRequest on unauthenticated session")
			stream.Close()
			mux.Session.Close()
			return
		}

		var req protocol.CopyRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}
		if err := r.RouteStream(req.TargetHostname, env, stream); err != nil {
			log.Println("[Relay] RouteStream copy error:", err)
		}
	})

	router.HandleFunc(string(protocol.TypeProxyRequest), func(stream net.Conn, env []byte) {
		sessionAuthMu.RLock()
		authed := isAuthenticated
		sessionAuthMu.RUnlock()

		if !authed {
			log.Println("[Relay] Dropping ProxyRequest on unauthenticated session")
			stream.Close()
			mux.Session.Close()
			return
		}

		var req protocol.ProxyRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}
		if err := r.RouteProxyStream(req.TargetHostname, env, stream); err != nil {
			log.Println("[Relay] RouteProxyStream error:", err)
		}
	})

	return router.Accept()
}

func (r *Relay) pingLoop(freq time.Duration) {
	ticker := time.NewTicker(freq)
	defer ticker.Stop()

	for {
		select {
		case <-r.closeCh:
			return
		case <-ticker.C:
			r.mu.RLock()
			for _, state := range r.nodes {
				state.Metadata.LastSeen = time.Now().UTC().Format(time.RFC3339)
			}
			r.mu.RUnlock()
		}
	}
}

// Domain returns the configured mesh domain suffix.
func (r *Relay) Domain() string {
	return r.domain
}

// ValidateToken verifies the provided token against the relay pre-shared token.
func (r *Relay) ValidateToken(provided string) bool {
	return protocol.ValidateToken(provided, r.token)
}

// RegisterNode registers an active node connection, displacing any existing session for the hostname.
func (r *Relay) RegisterNode(meta protocol.NodeMetadata, mux *protocol.StreamMultiplexer) (*NodeSession, error) {
	if meta.Hostname == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	if meta.ID == "" {
		meta.ID = meta.Hostname
	}
	if meta.Status == "" {
		meta.Status = "online"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if meta.ConnectedAt == "" {
		meta.ConnectedAt = now
	}
	meta.LastSeen = now

	r.mu.Lock()
	if existing, exists := r.nodes[meta.Hostname]; exists {
		if len(meta.Tags) == 0 && len(existing.Metadata.Tags) > 0 {
			meta.Tags = existing.Metadata.Tags
		}
		if existing.Mux != nil && existing.Mux != mux {
			log.Printf("[Relay] Renewing registration for %q (displacing previous session)\n", meta.Hostname)
			go existing.Mux.Session.Close()
		}
	}

	sess := &NodeSession{
		Mux:      mux,
		Metadata: meta,
	}
	r.nodes[meta.Hostname] = sess
	r.mu.Unlock()

	go r.BroadcastSync()

	// Monitor session closure
	go func() {
		<-mux.Session.CloseChan()
		r.mu.Lock()
		if curr, ok := r.nodes[meta.Hostname]; ok && curr.Mux == mux {
			delete(r.nodes, meta.Hostname)
		}
		r.mu.Unlock()
		r.BroadcastSync()
	}()

	return sess, nil
}

// UnregisterNode removes a node by hostname and triggers a sync broadcast.
func (r *Relay) UnregisterNode(hostname string) {
	r.mu.Lock()
	delete(r.nodes, hostname)
	r.mu.Unlock()
	go r.BroadcastSync()
}

// GetNode returns a copy of node metadata if online.
func (r *Relay) GetNode(hostname string) (*protocol.NodeMetadata, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	state, ok := r.nodes[hostname]
	if !ok {
		return nil, false
	}
	metaCopy := state.Metadata
	return &metaCopy, true
}

func (r *Relay) listNodesLocked() []protocol.NodeMetadata {
	list := make([]protocol.NodeMetadata, 0, len(r.nodes))
	for _, state := range r.nodes {
		list = append(list, state.Metadata)
	}
	return list
}

// ListNodes returns metadata for all currently connected nodes.
func (r *Relay) ListNodes() []protocol.NodeMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.listNodesLocked()
}

// RouteStream forwards an incoming stream and initial envelope to a target node.
func (r *Relay) RouteStream(targetHostname string, envelope []byte, srcStream net.Conn) error {
	r.mu.RLock()
	nodeState, ok := r.nodes[targetHostname]
	r.mu.RUnlock()

	if !ok {
		srcStream.Close()
		return fmt.Errorf("target node not found: %s", targetHostname)
	}

	targetStream, err := nodeState.Mux.Session.Open()
	if err != nil {
		srcStream.Close()
		return fmt.Errorf("failed to open stream to target node %s: %w", targetHostname, err)
	}

	if _, err := targetStream.Write(envelope); err != nil {
		targetStream.Close()
		srcStream.Close()
		return fmt.Errorf("failed to write envelope to target stream: %w", err)
	}

	go protocol.Proxy(srcStream, targetStream)
	return nil
}

// RouteProxyStream routes a TCP proxy request to a specified or default node.
func (r *Relay) RouteProxyStream(targetHostname string, envelope []byte, srcStream net.Conn) error {
	r.mu.RLock()
	var targetNode *NodeSession
	if targetHostname != "" {
		targetNode = r.nodes[targetHostname]
	} else {
		for _, n := range r.nodes {
			targetNode = n
			break
		}
	}
	r.mu.RUnlock()

	if targetNode == nil {
		srcStream.Close()
		return fmt.Errorf("no target node available for proxy stream")
	}

	targetStream, err := targetNode.Mux.Session.Open()
	if err != nil {
		srcStream.Close()
		return fmt.Errorf("failed to open proxy stream: %w", err)
	}

	if _, err := targetStream.Write(envelope); err != nil {
		targetStream.Close()
		srcStream.Close()
		return fmt.Errorf("failed to send proxy envelope: %w", err)
	}

	go protocol.Proxy(srcStream, targetStream)
	return nil
}

// ResolveDNS resolves an RFC 1035 wire query from a node against the active node registry.
func (r *Relay) ResolveDNS(req protocol.DNSQuery, proxyIP string) protocol.DNSResponse {
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

	domainSuffix := "." + r.domain + "."

	for _, q := range m.Question {
		name := strings.ToLower(q.Name)

		if !strings.HasSuffix(name, domainSuffix) {
			reply.Rcode = dns.RcodeNameError
			continue
		}

		prefix := strings.TrimSuffix(name, domainSuffix)
		parts := strings.Split(prefix, ".")
		nodeID := parts[len(parts)-1]

		r.mu.RLock()
		_, isOnline := r.nodes[nodeID]
		r.mu.RUnlock()

		if isOnline {
			ip := net.ParseIP(proxyIP)
			isIPv4 := ip != nil && ip.To4() != nil

			if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) && isIPv4 {
				rr, err := dns.NewRR(q.Name + " 10 IN A " + proxyIP)
				if err == nil {
					reply.Answer = append(reply.Answer, rr)
				}
			} else if (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) && !isIPv4 && ip != nil {
				rr, err := dns.NewRR(q.Name + " 10 IN AAAA " + proxyIP)
				if err == nil {
					reply.Answer = append(reply.Answer, rr)
				}
			}
		} else {
			reply.Rcode = dns.RcodeNameError
		}
	}

	if len(reply.Answer) > 0 {
		reply.Rcode = dns.RcodeSuccess
	}

	wire, err := reply.Pack()
	if err == nil {
		resp.Data = base64.StdEncoding.EncodeToString(wire)
	}
	resp.RCode = reply.Rcode
	if reply.Rcode == dns.RcodeNameError {
		resp.TTL = 5
	} else {
		resp.TTL = 10
	}

	return resp
}

// BroadcastSync broadcasts connected node metadata to all active nodes.
func (r *Relay) BroadcastSync() {
	r.mu.RLock()
	list := r.listNodesLocked()
	nodeSessions := make([]*NodeSession, 0, len(r.nodes))
	for _, s := range r.nodes {
		nodeSessions = append(nodeSessions, s)
	}
	r.mu.RUnlock()

	syncMsg := protocol.NodeSync{
		Type:  protocol.TypeNodeSync,
		Nodes: list,
	}

	b, err := json.Marshal(syncMsg)
	if err != nil {
		return
	}

	for _, s := range nodeSessions {
		if s.Mux != nil && s.Mux.Session != nil && !s.Mux.Session.IsClosed() {
			stream, err := s.Mux.Session.Open()
			if err == nil {
				stream.Write(b)
				stream.Close()
			}
		}
	}
}

// Close gracefully terminates the relay and ping loop.
func (r *Relay) Close() error {
	r.closeMux.Lock()
	defer r.closeMux.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	close(r.closeCh)

	r.mu.Lock()
	for _, s := range r.nodes {
		if s.Mux != nil && s.Mux.Session != nil {
			_ = s.Mux.Session.Close()
		}
	}
	r.nodes = make(map[string]*NodeSession)
	r.mu.Unlock()

	return nil
}
