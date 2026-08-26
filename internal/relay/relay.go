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
	"fabric/internal/version"

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
	Domain       string
	Token        string
	AdminToken   string
	PingFreq     time.Duration
	GatewayID    string
	Region       string
	FederationCA string
	Peers        []string
	LeafOf       string
}

// Relay is the deep control-plane module managing mesh node registration,
// session displacement, multiplexed stream routing, DNS wire resolution, and synchronization.
type Relay struct {
	domain       string
	token        string
	adminToken   string
	nodes        map[string]*NodeSession
	mu           sync.RWMutex
	closeCh      chan struct{}
	closed       bool
	closeMux     sync.Mutex

	// Federation fields
	gatewayID    string
	region       string
	federationCA string
	peers        map[string]*GatewayPeerSession
	remoteNodes  map[string]RemoteNodeEntry
	peerMu       sync.RWMutex
}

// New creates and initializes a new MeshRelay instance.
func New(cfg Config) *Relay {
	domain := cfg.Domain
	if domain == "" {
		domain = "fabric.mesh"
	}

	gatewayID := cfg.GatewayID
	if gatewayID == "" {
		gatewayID = "gw-" + strings.ReplaceAll(domain, ".", "-")
	}

	region := cfg.Region
	if region == "" {
		region = "default"
	}

	adminToken := cfg.AdminToken

	r := &Relay{
		domain:       domain,
		token:        cfg.Token,
		adminToken:   adminToken,
		nodes:        make(map[string]*NodeSession),
		closeCh:      make(chan struct{}),
		gatewayID:    gatewayID,
		region:       region,
		federationCA: cfg.FederationCA,
		peers:        make(map[string]*GatewayPeerSession),
		remoteNodes:  make(map[string]RemoteNodeEntry),
	}

	pingFreq := cfg.PingFreq
	if pingFreq > 0 {
		go r.pingLoop(pingFreq)
	}

	if cfg.LeafOf != "" {
		r.ConnectLeaf(cfg.LeafOf)
	}

	for _, p := range cfg.Peers {
		if p != "" {
			_ = r.AddPeer(p)
		}
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
			log.Println("[Server] Unauthorized connection attempt from:", hs.Hostname)
			mux.Session.Close()
			return
		}

		if hs.ProtocolVersion != "" && !version.IsProtocolCompatible(hs.ProtocolVersion, version.ProtocolVersion) {
			log.Printf("[Server] Handshake rejected: incompatible protocol version %q from %s (server protocol: %s)\n", hs.ProtocolVersion, hs.Hostname, version.ProtocolVersion)
			mux.Session.Close()
			return
		}

		if !protocol.IsValidHostname(hs.Hostname) {
			log.Println("[Server] Handshake rejected: invalid hostname (must match RFC 1123):", hs.Hostname)
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

		log.Printf("[Server] Node connected successfully: %s (session: %s)\n", hs.Hostname, sessID)
	})

	requireAuth := func(name string, handler func(stream net.Conn, env []byte)) func(stream net.Conn, env []byte) {
		return func(stream net.Conn, env []byte) {
			sessionAuthMu.RLock()
			authed := isAuthenticated
			sessionAuthMu.RUnlock()

			if !authed {
				log.Printf("[Server] Dropping %s on unauthenticated session\n", name)
				stream.Close()
				mux.Session.Close()
				return
			}
			handler(stream, env)
		}
	}

	router.HandleFunc(string(protocol.TypeDNSQuery), requireAuth("DNS query", func(stream net.Conn, env []byte) {
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
	}))

	router.HandleFunc(string(protocol.TypeExecRequest), requireAuth("ExecRequest", func(stream net.Conn, env []byte) {
		var req protocol.ExecRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}
		log.Printf("[Server] Exec request targeting %s: %s\n", req.TargetHostname, req.Command)
		if err := r.RouteStream(req.TargetHostname, env, stream); err != nil {
			log.Println("[Server] RouteStream error:", err)
		}
	}))

	router.HandleFunc(string(protocol.TypeCopyRequest), requireAuth("CopyRequest", func(stream net.Conn, env []byte) {
		var req protocol.CopyRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}
		if err := r.RouteStream(req.TargetHostname, env, stream); err != nil {
			log.Println("[Server] RouteStream copy error:", err)
		}
	}))

	router.HandleFunc(string(protocol.TypeProxyRequest), requireAuth("ProxyRequest", func(stream net.Conn, env []byte) {
		var req protocol.ProxyRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}
		if err := r.RouteProxyStream(req.TargetHostname, env, stream); err != nil {
			log.Println("[Server] RouteProxyStream error:", err)
		}
	}))

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
			r.mu.Lock()
			nowStr := time.Now().UTC().Format(time.RFC3339)
			for _, state := range r.nodes {
				state.Metadata.LastSeen = nowStr
			}
			r.mu.Unlock()
		}
	}
}

// Domain returns the configured mesh domain suffix.
func (r *Relay) Domain() string {
	return r.domain
}

// ValidateToken verifies the provided token against the relay pre-shared token or admin token.
func (r *Relay) ValidateToken(provided string) bool {
	if protocol.ValidateToken(provided, r.token) {
		return true
	}
	if r.adminToken != "" && protocol.ValidateToken(provided, r.adminToken) {
		return true
	}
	return false
}

// ValidateAdminToken verifies the provided token against the configured administrative token.
func (r *Relay) ValidateAdminToken(provided string) bool {
	if r.adminToken != "" && protocol.ValidateToken(provided, r.adminToken) {
		return true
	}
	return false
}

// RegisterNode registers an active node connection, displacing any existing session for the hostname.
func (r *Relay) RegisterNode(meta protocol.NodeMetadata, mux *protocol.StreamMultiplexer) (*NodeSession, error) {
	if meta.Hostname == "" {
		return nil, fmt.Errorf("empty hostname")
	}
	if !protocol.IsValidHostname(meta.Hostname) {
		return nil, fmt.Errorf("invalid hostname %q: must match RFC 1123 DNS naming rules", meta.Hostname)
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
	meta.GatewayID = r.gatewayID

	r.mu.Lock()
	if existing, exists := r.nodes[meta.Hostname]; exists {
		if len(meta.Tags) == 0 && len(existing.Metadata.Tags) > 0 {
			meta.Tags = existing.Metadata.Tags
		}
		if existing.Mux != nil && existing.Mux != mux {
			log.Printf("[Server] Renewing registration for %q (displacing previous session)\n", meta.Hostname)
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
	go r.BroadcastThreadAdvertise([]protocol.NodeMetadata{meta})

	// Monitor session closure
	if mux != nil && mux.Session != nil {
		go func() {
			<-mux.Session.CloseChan()
			r.mu.Lock()
			if curr, ok := r.nodes[meta.Hostname]; ok && curr.Mux == mux {
				delete(r.nodes, meta.Hostname)
			}
			r.mu.Unlock()
			r.BroadcastSync()
			r.BroadcastThreadWithdraw(meta.Hostname)
		}()
	}

	return sess, nil
}

// UnregisterNode removes a node by hostname and triggers a sync broadcast.
func (r *Relay) UnregisterNode(hostname string) {
	r.mu.Lock()
	delete(r.nodes, hostname)
	r.mu.Unlock()
	go r.BroadcastSync()
	go r.BroadcastThreadWithdraw(hostname)
}

// GetNode returns a copy of node metadata if online (local or remote).
func (r *Relay) GetNode(hostname string) (*protocol.NodeMetadata, bool) {
	r.mu.RLock()
	state, ok := r.nodes[hostname]
	var metaCopy protocol.NodeMetadata
	if ok {
		metaCopy = state.Metadata
	}
	r.mu.RUnlock()

	if ok {
		return &metaCopy, true
	}

	// Check remote nodes
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()

	if rentry, exists := r.remoteNodes[hostname]; exists {
		metaCopy := rentry.Node
		return &metaCopy, true
	}

	// Check if hostname is formatted as <thread>.<gateway-id> or <thread>.<gateway-id>.<domain>
	if idx := strings.Index(hostname, "."); idx > 0 {
		prefix := hostname[:idx]
		rest := hostname[idx+1:]
		for rHost, rentry := range r.remoteNodes {
			if rHost == prefix && (rentry.GatewayID == rest || rentry.GatewayID+"."+r.domain == rest || rentry.GatewayID+".fabric" == rest) {
				metaCopy := rentry.Node
				return &metaCopy, true
			}
		}
	}

	return nil, false
}

func (r *Relay) listNodesLocked() []protocol.NodeMetadata {
	list := make([]protocol.NodeMetadata, 0, len(r.nodes))
	for _, state := range r.nodes {
		meta := state.Metadata
		if meta.GatewayID == "" {
			meta.GatewayID = r.gatewayID
		}
		list = append(list, meta)
	}
	return list
}

// ListNodes returns metadata for all currently connected local and federated nodes.
func (r *Relay) ListNodes() []protocol.NodeMetadata {
	r.mu.RLock()
	list := r.listNodesLocked()
	r.mu.RUnlock()

	r.peerMu.RLock()
	for _, rentry := range r.remoteNodes {
		list = append(list, rentry.Node)
	}
	r.peerMu.RUnlock()

	return list
}

func (r *Relay) resolveTarget(targetHostname string) (isLocal bool, nodeSess *NodeSession, peerSess *GatewayPeerSession, cleanTarget string) {
	cleanTarget = targetHostname
	gwHint := ""

	if idx := strings.Index(targetHostname, "."); idx > 0 {
		cleanTarget = targetHostname[:idx]
		gwHint = targetHostname[idx+1:]
		if strings.HasSuffix(gwHint, "."+r.domain) {
			gwHint = strings.TrimSuffix(gwHint, "."+r.domain)
		}
		if strings.HasSuffix(gwHint, ".fabric") {
			gwHint = strings.TrimSuffix(gwHint, ".fabric")
		}
	}

	// 1. If gwHint is local gateway or empty, check local nodes
	if gwHint == "" || gwHint == r.gatewayID {
		r.mu.RLock()
		sess, ok := r.nodes[cleanTarget]
		r.mu.RUnlock()
		if ok {
			return true, sess, nil, cleanTarget
		}
	}

	// 2. Check remote nodes
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()

	if gwHint != "" {
		for rHost, rentry := range r.remoteNodes {
			if rHost == cleanTarget && rentry.GatewayID == gwHint {
				return false, nil, rentry.PeerSession, cleanTarget
			}
		}
		if p, ok := r.peers[gwHint]; ok {
			return false, nil, p, cleanTarget
		}
	}

	if rentry, ok := r.remoteNodes[cleanTarget]; ok {
		return false, nil, rentry.PeerSession, cleanTarget
	}

	return false, nil, nil, cleanTarget
}

// RouteStream forwards an incoming stream and initial envelope to a target node (local or federated).
func (r *Relay) RouteStream(targetHostname string, envelope []byte, srcStream net.Conn) error {
	isLocal, localNode, peerSess, cleanTarget := r.resolveTarget(targetHostname)

	if isLocal && localNode != nil {
		targetStream, err := localNode.Mux.Session.Open()
		if err != nil {
			srcStream.Close()
			return fmt.Errorf("failed to open stream to target node %s: %w", cleanTarget, err)
		}

		if _, err := targetStream.Write(envelope); err != nil {
			targetStream.Close()
			srcStream.Close()
			return fmt.Errorf("failed to write envelope to target stream: %w", err)
		}

		go protocol.Proxy(srcStream, targetStream)
		return nil
	}

	if peerSess != nil && peerSess.Mux != nil && peerSess.Mux.Session != nil {
		// Parse envelope to verify and update loop avoidance headers
		var rawMap map[string]interface{}
		if err := json.Unmarshal(envelope, &rawMap); err == nil {
			pathList := []string{}
			if p, ok := rawMap["path"].([]interface{}); ok {
				for _, elem := range p {
					if s, ok := elem.(string); ok {
						if s == r.gatewayID {
							srcStream.Close()
							return fmt.Errorf("circular routing loop detected for target %s: path=%v", targetHostname, p)
						}
						pathList = append(pathList, s)
					}
				}
			}
			pathList = append(pathList, r.gatewayID)
			rawMap["path"] = pathList

			hops := 0
			if h, ok := rawMap["hops"].(float64); ok {
				hops = int(h)
			}
			rawMap["hops"] = hops + 1

			// Update target_hostname to cleanTarget for next hop
			rawMap["target_hostname"] = cleanTarget

			envelope, _ = json.Marshal(rawMap)
		}

		targetStream, err := peerSess.Mux.Session.Open()
		if err != nil {
			srcStream.Close()
			return fmt.Errorf("failed to open stream to peer gateway %s: %w", peerSess.GatewayID, err)
		}

		if _, err := targetStream.Write(envelope); err != nil {
			targetStream.Close()
			srcStream.Close()
			return fmt.Errorf("failed to write envelope to peer stream: %w", err)
		}

		go protocol.Proxy(srcStream, targetStream)
		return nil
	}

	srcStream.Close()
	return fmt.Errorf("target node not found: %s", targetHostname)
}

// RouteProxyStream routes a TCP proxy request to a specified or default node (local or federated).
func (r *Relay) RouteProxyStream(targetHostname string, envelope []byte, srcStream net.Conn) error {
	if targetHostname == "" {
		r.mu.RLock()
		for _, n := range r.nodes {
			targetHostname = n.Metadata.Hostname
			break
		}
		r.mu.RUnlock()
	}

	isLocal, localNode, peerSess, cleanTarget := r.resolveTarget(targetHostname)

	if isLocal && localNode != nil {
		targetStream, err := localNode.Mux.Session.Open()
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

	if peerSess != nil && peerSess.Mux != nil && peerSess.Mux.Session != nil {
		var rawMap map[string]interface{}
		if err := json.Unmarshal(envelope, &rawMap); err == nil {
			pathList := []string{}
			if p, ok := rawMap["path"].([]interface{}); ok {
				for _, elem := range p {
					if s, ok := elem.(string); ok {
						if s == r.gatewayID {
							srcStream.Close()
							return fmt.Errorf("circular routing loop detected for proxy target %s: path=%v", targetHostname, p)
						}
						pathList = append(pathList, s)
					}
				}
			}
			pathList = append(pathList, r.gatewayID)
			rawMap["path"] = pathList
			rawMap["target_hostname"] = cleanTarget

			envelope, _ = json.Marshal(rawMap)
		}

		targetStream, err := peerSess.Mux.Session.Open()
		if err != nil {
			srcStream.Close()
			return fmt.Errorf("failed to open proxy stream to peer gateway %s: %w", peerSess.GatewayID, err)
		}

		if _, err := targetStream.Write(envelope); err != nil {
			targetStream.Close()
			srcStream.Close()
			return fmt.Errorf("failed to write proxy envelope to peer stream: %w", err)
		}

		go protocol.Proxy(srcStream, targetStream)
		return nil
	}

	srcStream.Close()
	return fmt.Errorf("no target node available for proxy stream: %s", targetHostname)
}

// ResolveDNS resolves an RFC 1035 wire query from a node against active local and federated registries.
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

	for _, q := range m.Question {
		name := strings.ToLower(q.Name)

		prefix := ""
		matched := false
		for _, s := range []string{"." + r.domain + ".", ".fabric.", ".mesh."} {
			if strings.HasSuffix(name, s) {
				prefix = strings.TrimSuffix(name, s)
				matched = true
				break
			}
		}

		if !matched {
			reply.Rcode = dns.RcodeNameError
			continue
		}

		parts := strings.Split(prefix, ".")
		nodeID := parts[len(parts)-1]
		gwID := ""

		if len(parts) > 1 {
			last := parts[len(parts)-1]
			// Check if last part is a known gateway ID
			r.peerMu.RLock()
			_, isPeer := r.peers[last]
			if !isPeer {
				for _, rn := range r.remoteNodes {
					if rn.GatewayID == last {
						isPeer = true
						break
					}
				}
			}
			r.peerMu.RUnlock()

			if last == r.gatewayID || isPeer {
				gwID = last
				nodeID = parts[len(parts)-2]
			}
		}

		isOnline := false

		if gwID == "" || gwID == r.gatewayID {
			r.mu.RLock()
			_, isOnline = r.nodes[nodeID]
			r.mu.RUnlock()
		}

		if !isOnline {
			r.peerMu.RLock()
			for rHost, rentry := range r.remoteNodes {
				if rHost == nodeID && (gwID == "" || rentry.GatewayID == gwID) {
					isOnline = true
					break
				}
			}
			r.peerMu.RUnlock()
		}

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

	r.peerMu.Lock()
	for _, p := range r.peers {
		if p.Mux != nil && p.Mux.Session != nil {
			_ = p.Mux.Session.Close()
		}
	}
	r.peers = make(map[string]*GatewayPeerSession)
	r.remoteNodes = make(map[string]RemoteNodeEntry)
	r.peerMu.Unlock()

	return nil
}
