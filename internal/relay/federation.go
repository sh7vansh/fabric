package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/version"

	"github.com/gorilla/websocket"
)

// GatewayPeerSession manages an active multiplexed peering session to another fabric-server peer.
type GatewayPeerSession struct {
	ServerID     string
	GatewayID    string
	Domain       string
	Region       string
	Capabilities []string
	Topology     string // "core" or "leaf"
	Mux          *protocol.StreamMultiplexer
	Endpoint     string
	ConnectedAt  time.Time
	RTT          time.Duration
	IsOutbound   bool

	closeCh chan struct{}
	closed  bool
	mu      sync.Mutex
}

// ServerPeerSession is the canonical name for GatewayPeerSession.
type ServerPeerSession = GatewayPeerSession

// RemoteNodeEntry maps a remote thread hostname to its hosting server.
type RemoteNodeEntry struct {
	Node        protocol.NodeMetadata
	ServerID    string
	GatewayID   string
	PeerSession *GatewayPeerSession
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

// ServerID returns the local server's unique federation ServerID.
func (r *Relay) ServerID() string {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()
	return r.gatewayID
}

// GatewayID returns the local server's unique federation GatewayID (deprecated alias for ServerID).
func (r *Relay) GatewayID() string {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()
	return r.gatewayID
}

// Region returns the local server's configured federation region.
func (r *Relay) Region() string {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()
	return r.region
}

// FederationCA returns the local server's configured federation CA certificate path.
func (r *Relay) FederationCA() string {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()
	return r.federationCA
}

// RegisterPeer registers an active server peer session, handling deduplication.
func (r *Relay) RegisterPeer(peer *GatewayPeerSession) error {
	if peer == nil {
		return fmt.Errorf("invalid peer session")
	}
	if peer.ServerID == "" && peer.GatewayID != "" {
		peer.ServerID = peer.GatewayID
	}
	if peer.GatewayID == "" && peer.ServerID != "" {
		peer.GatewayID = peer.ServerID
	}
	if peer.ServerID == "" {
		return fmt.Errorf("invalid peer session or empty server ID")
	}

	if peer.ServerID == r.gatewayID {
		return fmt.Errorf("cannot peer with self (%s)", r.gatewayID)
	}

	if peer.Topology == "" {
		peer.Topology = "core"
	}
	if peer.ConnectedAt.IsZero() {
		peer.ConnectedAt = time.Now().UTC()
	}
	peer.closeCh = make(chan struct{})

	r.peerMu.Lock()
	if existing, exists := r.peers[peer.GatewayID]; exists {
		// Tie-breaker: Lexicographical comparison in symmetric core peering
		// When both servers dial each other simultaneously, keep the connection initiated
		// by the server with the lexicographically smaller ServerID.
		if peer.Topology == "core" && existing.Topology == "core" && existing.IsOutbound != peer.IsOutbound {
			preferOutbound := r.gatewayID < peer.GatewayID
			if peer.IsOutbound != preferOutbound {
				r.peerMu.Unlock()
				log.Printf("[Relay/Peering] Duplicate peer connection for %q dropped by tie-breaker (prefer outbound=%v, new is outbound=%v)", peer.GatewayID, preferOutbound, peer.IsOutbound)
				if peer.Mux != nil && peer.Mux.Session != nil {
					go peer.Mux.Session.Close()
				}
				return fmt.Errorf("duplicate peer connection for %q dropped by tie-breaker", peer.GatewayID)
			}
		}

		log.Printf("[Relay/Peering] Duplicate peer connection for %q detected; replacing existing session", peer.GatewayID)
		if existing.Mux != nil && existing.Mux.Session != nil {
			go existing.Mux.Session.Close()
		}
	}
	r.peers[peer.GatewayID] = peer
	r.peerMu.Unlock()

	log.Printf("[Relay/Peering] Peered successfully with server %q (region: %s, topology: %s)\n", peer.GatewayID, peer.Region, peer.Topology)

	// Send current local nodes to newly joined peer
	go r.sendLocalThreadAdvertisementsToPeer(peer)

	// Monitor session disconnect
	if peer.Mux != nil && peer.Mux.Session != nil {
		go func() {
			<-peer.Mux.Session.CloseChan()
			r.unregisterPeerSession(peer)
		}()
	}

	return nil
}

func (r *Relay) unregisterPeerSession(peer *GatewayPeerSession) {
	if peer == nil {
		return
	}
	r.peerMu.Lock()
	if curr, ok := r.peers[peer.GatewayID]; ok && curr == peer {
		delete(r.peers, peer.GatewayID)
		for host, entry := range r.remoteNodes {
			if entry.GatewayID == peer.GatewayID {
				delete(r.remoteNodes, host)
			}
		}
		if r.reconciler != nil {
			r.reconciler.ResetPeer(peer.GatewayID)
		}
		peer.mu.Lock()
		if !peer.closed {
			peer.closed = true
			close(peer.closeCh)
		}
		peer.mu.Unlock()
		log.Printf("[Relay/Peering] Peer %q disconnected and its routes withdrawn\n", peer.GatewayID)
	}
	r.peerMu.Unlock()
}

// UnregisterPeer removes a peer and cleans up all remote threads hosted by it.
func (r *Relay) UnregisterPeer(gatewayID string) {
	r.peerMu.Lock()
	peer, exists := r.peers[gatewayID]
	if exists {
		delete(r.peers, gatewayID)
		for host, entry := range r.remoteNodes {
			if entry.GatewayID == gatewayID {
				delete(r.remoteNodes, host)
			}
		}
		if r.reconciler != nil {
			r.reconciler.ResetPeer(gatewayID)
		}
	}
	r.peerMu.Unlock()

	if exists && peer != nil {
		peer.mu.Lock()
		if !peer.closed {
			peer.closed = true
			close(peer.closeCh)
		}
		peer.mu.Unlock()
		if peer.Mux != nil && peer.Mux.Session != nil {
			_ = peer.Mux.Session.Close()
		}
		log.Printf("[Relay/Peering] Peer %q removed\n", gatewayID)
	}
}

// RegisterRemoteNode records an advertised thread hosted on a remote peer gateway.
func (r *Relay) RegisterRemoteNode(node protocol.NodeMetadata, gatewayID string) {
	if node.Hostname == "" || gatewayID == "" {
		return
	}

	r.peerMu.Lock()
	defer r.peerMu.Unlock()

	peer := r.peers[gatewayID]
	node.GatewayID = gatewayID
	if node.Status == "" {
		node.Status = "online [peer: " + gatewayID + "]"
	}

	r.remoteNodes[node.Hostname] = RemoteNodeEntry{
		Node:        node,
		GatewayID:   gatewayID,
		PeerSession: peer,
	}
}

// UnregisterRemoteNode removes an advertised thread.
func (r *Relay) UnregisterRemoteNode(hostname, gatewayID string) {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()

	if entry, ok := r.remoteNodes[hostname]; ok {
		if gatewayID == "" || entry.GatewayID == gatewayID {
			delete(r.remoteNodes, hostname)
		}
	}
}

// ListPeers returns summary telemetry for all active peer gateways.
func (r *Relay) ListPeers() []protocol.GatewayPeerInfo {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()

	list := make([]protocol.GatewayPeerInfo, 0, len(r.peers))
	for _, p := range r.peers {
		threadCount := 0
		for _, rn := range r.remoteNodes {
			if rn.GatewayID == p.GatewayID {
				threadCount++
			}
		}

		rttStr := "0ms"
		if p.RTT > 0 {
			rttStr = p.RTT.Round(time.Millisecond).String()
		}

		list = append(list, protocol.ServerPeerInfo{
			ServerID:     p.GatewayID,
			GatewayID:    p.GatewayID,
			Domain:       p.Domain,
			Region:       p.Region,
			Capabilities: p.Capabilities,
			Status:       "connected",
			Topology:     p.Topology,
			RTT:          rttStr,
			ThreadCount:  threadCount,
			ConnectedAt:  p.ConnectedAt.Format(time.RFC3339),
			Endpoint:     p.Endpoint,
		})
	}
	return list
}

// GetPeer retrieves telemetry for a single peer server.
func (r *Relay) GetPeer(gatewayID string) (*protocol.ServerPeerInfo, bool) {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()

	p, ok := r.peers[gatewayID]
	if !ok {
		return nil, false
	}

	threadCount := 0
	for _, rn := range r.remoteNodes {
		if rn.GatewayID == p.GatewayID {
			threadCount++
		}
	}

	rttStr := "0ms"
	if p.RTT > 0 {
		rttStr = p.RTT.Round(time.Millisecond).String()
	}

	info := protocol.ServerPeerInfo{
		ServerID:     p.GatewayID,
		GatewayID:    p.GatewayID,
		Domain:       p.Domain,
		Region:       p.Region,
		Capabilities: p.Capabilities,
		Status:       "connected",
		Topology:     p.Topology,
		RTT:          rttStr,
		ThreadCount:  threadCount,
		ConnectedAt:  p.ConnectedAt.Format(time.RFC3339),
		Endpoint:     p.Endpoint,
	}
	return &info, true
}

// RemovePeer disconnects and removes a peer gateway.
func (r *Relay) RemovePeer(gatewayID string) error {
	r.peerMu.RLock()
	peer, ok := r.peers[gatewayID]
	r.peerMu.RUnlock()

	if !ok {
		return fmt.Errorf("peer gateway %q not found", gatewayID)
	}

	if peer.Mux != nil && peer.Mux.Session != nil {
		_ = peer.Mux.Session.Close()
	}
	r.UnregisterPeer(gatewayID)
	return nil
}

// AddPeer initiates an outbound connection to a target gateway endpoint.
func (r *Relay) AddPeer(endpoint string) error {
	go r.connectOutboundPeerWithBackoff(endpoint, false)
	return nil
}

// ConnectLeaf initiates an outbound leaf reverse tunnel connection to a core gateway.
func (r *Relay) ConnectLeaf(coreEndpoint string) {
	go r.connectOutboundPeerWithBackoff(coreEndpoint, true)
}

func (r *Relay) connectOutboundPeerWithBackoff(rawEndpoint string, isLeaf bool) {
	baseBackoff := 1 * time.Second
	maxBackoff := 30 * time.Second
	backoff := baseBackoff

	for {
		select {
		case <-r.closeCh:
			return
		default:
		}

		err := r.dialAndRunPeerSession(rawEndpoint, isLeaf)
		if err != nil {
			log.Printf("[Relay/Peering] Outbound connection to %s failed (%v); reconnecting in %v...", rawEndpoint, err, backoff)
		}

		select {
		case <-r.closeCh:
			return
		case <-time.After(backoff):
		}

		// Exponential backoff with jitter
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		backoff = backoff*2 + jitter
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (r *Relay) dialAndRunPeerSession(rawEndpoint string, isLeaf bool) error {
	u, err := pki.NormalizeURL(rawEndpoint)
	if err != nil {
		return fmt.Errorf("invalid peer url: %w", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/gateway/v1/peer"
	}

	header := http.Header{}
	if r.token != "" {
		header.Add("Authorization", "Bearer "+r.token)
	}

	var dialer *pki.SecureDialer
	if r.federationCA != "" {
		d, err := pki.NewFederationSecureDialer(r.federationCA, nil)
		if err != nil {
			return fmt.Errorf("failed to build federation SecureDialer: %w", err)
		}
		dialer = d
	} else {
		d, err := pki.NewSecureDialer("")
		if err != nil {
			return fmt.Errorf("failed to build client SecureDialer: %w", err)
		}
		dialer = d
	}

	conn, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		return fmt.Errorf("dial peer ws (%s): %w", u.String(), err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return fmt.Errorf("stream multiplexer failed: %w", err)
	}

	// Send initial GatewayHello
	stream, err := mux.Session.Open()
	if err != nil {
		return fmt.Errorf("failed to open handshake stream: %w", err)
	}

	hello := protocol.GatewayHello{
		Type:            protocol.TypeGatewayHello,
		GatewayID:       r.gatewayID,
		ServerID:        r.gatewayID,
		Domain:          r.domain,
		Region:          r.region,
		Capabilities:    []string{"exec", "cp", "proxy", "dns"},
		Token:           r.token,
		IsLeaf:          isLeaf,
		Version:         version.Version,
		ProtocolVersion: version.ProtocolVersion,
	}
	b, _ := json.Marshal(hello)
	if _, err := stream.Write(b); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write hello envelope: %w", err)
	}

	// Read peer hello response
	var remoteHello protocol.GatewayHello
	decoder := json.NewDecoder(stream)
	if err := decoder.Decode(&remoteHello); err != nil {
		stream.Close()
		return fmt.Errorf("failed to read remote peer hello: %w", err)
	}
	stream.Close()

	if remoteHello.ProtocolVersion != "" && !version.IsProtocolCompatible(remoteHello.ProtocolVersion, version.ProtocolVersion) {
		return fmt.Errorf("incompatible remote peer protocol version %q (local protocol: %s)", remoteHello.ProtocolVersion, version.ProtocolVersion)
	}

	topology := "core"
	if isLeaf || remoteHello.IsLeaf {
		topology = "leaf"
	}

	peerSession := &GatewayPeerSession{
		GatewayID:    remoteHello.GatewayID,
		Domain:       remoteHello.Domain,
		Region:       remoteHello.Region,
		Capabilities: remoteHello.Capabilities,
		Topology:     topology,
		Mux:          mux,
		Endpoint:     rawEndpoint,
		ConnectedAt:  time.Now().UTC(),
		IsOutbound:   true,
	}

	if err := r.RegisterPeer(peerSession); err != nil {
		return err
	}

	return r.ServePeerMux(mux, rawEndpoint, isLeaf, remoteHello.GatewayID)
}

// ServePeerWS handles an incoming peer WebSocket connection.
func (r *Relay) ServePeerWS(conn *websocket.Conn, remoteAddr string, isLeaf bool) error {
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, true)
	if err != nil {
		return err
	}

	return r.ServePeerMux(mux, remoteAddr, isLeaf, "")
}

// ServePeerMux handles routing and multiplexing on a peer Yamux session.
func (r *Relay) ServePeerMux(mux *protocol.StreamMultiplexer, remoteAddr string, isLeaf bool, peerGatewayID string) error {
	router := protocol.NewRouter(mux.Session)

	var currentPeerMu sync.Mutex
	var currentPeer *GatewayPeerSession

	if peerGatewayID != "" {
		r.peerMu.RLock()
		currentPeer = r.peers[peerGatewayID]
		r.peerMu.RUnlock()
		if currentPeer == nil {
			currentPeer = &GatewayPeerSession{
				ServerID:  peerGatewayID,
				GatewayID: peerGatewayID,
				Mux:       mux,
			}
		}
	}

	setRegisteredPeer := func(p *GatewayPeerSession) {
		currentPeerMu.Lock()
		currentPeer = p
		currentPeerMu.Unlock()
	}

	getRegisteredPeer := func() *GatewayPeerSession {
		currentPeerMu.Lock()
		defer currentPeerMu.Unlock()
		return currentPeer
	}

	requirePeerAuth := func(name string, handler func(stream net.Conn, env []byte)) func(stream net.Conn, env []byte) {
		return func(stream net.Conn, env []byte) {
			if getRegisteredPeer() == nil {
				log.Printf("[Relay/Peering] Dropping %s on unauthenticated peer session\n", name)
				stream.Close()
				mux.Session.Close()
				return
			}
			handler(stream, env)
		}
	}

	// 1. Server Handshake
	handleHello := func(stream net.Conn, env []byte) {
		defer stream.Close()

		var hello protocol.ServerHello
		if err := json.Unmarshal(env, &hello); err != nil {
			mux.Session.Close()
			return
		}

		if hello.Token != "" && !r.ValidateToken(hello.Token) {
			log.Printf("[Relay/Peering] Unauthorized peer connection attempt from: %s\n", hello.ServerID)
			mux.Session.Close()
			return
		}
		if r.federationCA == "" && (hello.Token == "" || !r.ValidateToken(hello.Token)) {
			log.Printf("[Relay/Peering] Unauthorized peer connection attempt (missing/invalid token) from: %s\n", hello.ServerID)
			mux.Session.Close()
			return
		}

		if hello.ProtocolVersion != "" && !version.IsProtocolCompatible(hello.ProtocolVersion, version.ProtocolVersion) {
			log.Printf("[Relay/Peering] Incompatible peer protocol version %q from %s (server protocol: %s)\n", hello.ProtocolVersion, hello.ServerID, version.ProtocolVersion)
			mux.Session.Close()
			return
		}

		if hello.ServerID == "" {
			mux.Session.Close()
			return
		}

		// Reply with local ServerHello
		myHello := protocol.ServerHello{
			Type:            protocol.TypeServerHello,
			ServerID:        r.gatewayID,
			GatewayID:       r.gatewayID,
			Domain:          r.domain,
			Region:          r.region,
			Capabilities:    []string{"exec", "cp", "proxy", "dns"},
			IsLeaf:          isLeaf,
			Version:         version.Version,
			ProtocolVersion: version.ProtocolVersion,
		}
		replyBytes, _ := json.Marshal(myHello)
		_, _ = stream.Write(replyBytes)

		topology := "core"
		if hello.IsLeaf || isLeaf {
			topology = "leaf"
		}

		peerSession := &GatewayPeerSession{
			ServerID:     hello.ServerID,
			GatewayID:    hello.ServerID,
			Domain:       hello.Domain,
			Region:       hello.Region,
			Capabilities: hello.Capabilities,
			Topology:     topology,
			Mux:          mux,
			Endpoint:     remoteAddr,
			ConnectedAt:  time.Now().UTC(),
		}

		setRegisteredPeer(peerSession)
		if err := r.RegisterPeer(peerSession); err != nil {
			log.Printf("[Relay/Peering] Failed to register peer %s: %v\n", hello.ServerID, err)
			mux.Session.Close()
			return
		}
	}
	router.HandleFunc(string(protocol.TypeServerHello), handleHello)
	router.HandleFunc(string(protocol.TypeGatewayHello), handleHello)

	// 2. Thread Advertisement
	router.HandleFunc(string(protocol.TypeThreadAdvertise), requirePeerAuth("ThreadAdvertise", func(stream net.Conn, env []byte) {
		defer stream.Close()

		var adv protocol.ThreadAdvertise
		if err := json.Unmarshal(env, &adv); err != nil {
			return
		}

		if r.reconciler != nil && adv.Epoch > 0 {
			isNewer, needsSync := r.reconciler.ValidateAndRecordEpoch(adv.GatewayID, adv.Epoch, adv.Checksum)
			if !isNewer {
				log.Printf("[Relay/Peering] Discarding stale ThreadAdvertise (epoch %d < latest) from %s\n", adv.Epoch, adv.GatewayID)
				return
			}
			if needsSync {
				log.Printf("[Relay/Peering] Checksum mismatch from %s, triggering delta synchronization\n", adv.GatewayID)
			}
		}

		for _, node := range adv.Nodes {
			r.RegisterRemoteNode(node, adv.GatewayID)
		}
	}))

	// 3. Thread Withdrawal
	router.HandleFunc(string(protocol.TypeThreadWithdraw), requirePeerAuth("ThreadWithdraw", func(stream net.Conn, env []byte) {
		defer stream.Close()

		var with protocol.ThreadWithdraw
		if err := json.Unmarshal(env, &with); err != nil {
			return
		}

		if r.reconciler != nil && with.Epoch > 0 {
			isNewer, _ := r.reconciler.ValidateAndRecordEpoch(with.GatewayID, with.Epoch, with.Checksum)
			if !isNewer {
				log.Printf("[Relay/Peering] Discarding stale ThreadWithdraw (epoch %d < latest) from %s\n", with.Epoch, with.GatewayID)
				return
			}
		}

		r.UnregisterRemoteNode(with.Hostname, with.GatewayID)
	}))

	// Heartbeats and keepalives with topology checksum comparison
	handleHeartbeat := func(stream net.Conn, env []byte) {
		defer stream.Close()
		var hb protocol.ServerHeartbeat
		if err := json.Unmarshal(env, &hb); err != nil {
			return
		}
		if r.reconciler != nil && hb.Epoch > 0 {
			isNewer, needsSync := r.reconciler.ValidateAndRecordEpoch(hb.GatewayID, hb.Epoch, hb.Checksum)
			if isNewer && needsSync {
				log.Printf("[Relay/Peering] Topology checksum mismatch with peer %s; requesting delta synchronization\n", hb.GatewayID)
				r.peerMu.RLock()
				peer := r.peers[hb.GatewayID]
				r.peerMu.RUnlock()
				if peer != nil {
					go r.sendLocalThreadAdvertisementsToPeer(peer)
				}
			}
		}
	}
	router.HandleFunc(string(protocol.TypeServerHeartbeat), requirePeerAuth("ServerHeartbeat", handleHeartbeat))
	router.HandleFunc(string(protocol.TypeGatewayHeartbeat), requirePeerAuth("GatewayHeartbeat", handleHeartbeat))

	// Topology delta synchronization request
	router.HandleFunc(string(protocol.TypeTopologySyncRequest), requirePeerAuth("TopologySyncRequest", func(stream net.Conn, env []byte) {
		defer stream.Close()
		var syncReq protocol.TopologySyncRequest
		if err := json.Unmarshal(env, &syncReq); err != nil {
			return
		}
		r.peerMu.RLock()
		peer := r.peers[syncReq.GatewayID]
		r.peerMu.RUnlock()
		if peer != nil {
			go r.sendLocalThreadAdvertisementsToPeer(peer)
		}
	}))

	// 4. Cross-gateway ExecRequest
	router.HandleFunc(string(protocol.TypeExecRequest), requirePeerAuth("ExecRequest", func(stream net.Conn, env []byte) {
		var req protocol.ExecRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}

		// Loop avoidance check
		for _, p := range req.Path {
			if p == r.gatewayID {
				log.Printf("[Relay/Peering] Circular routing loop detected for ExecRequest path=%v, dropping\n", req.Path)
				stream.Close()
				return
			}
		}

		cleanTarget := r.cleanTargetHostname(req.TargetHostname)
		multiReader := io.MultiReader(strings.NewReader(""), stream)
		prefixedConn := &prefixConn{Conn: stream, r: multiReader}

		if err := r.RouteStream(cleanTarget, env, prefixedConn); err != nil {
			log.Printf("[Relay/Peering] Failed to route ExecRequest to %s: %v\n", cleanTarget, err)
		}
	}))

	// 5. Cross-gateway CopyRequest
	router.HandleFunc(string(protocol.TypeCopyRequest), requirePeerAuth("CopyRequest", func(stream net.Conn, env []byte) {
		var req protocol.CopyRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}

		for _, p := range req.Path {
			if p == r.gatewayID {
				log.Printf("[Relay/Peering] Circular routing loop detected for CopyRequest path=%v, dropping\n", req.Path)
				stream.Close()
				return
			}
		}

		cleanTarget := r.cleanTargetHostname(req.TargetHostname)
		multiReader := io.MultiReader(strings.NewReader(""), stream)
		prefixedConn := &prefixConn{Conn: stream, r: multiReader}

		if err := r.RouteStream(cleanTarget, env, prefixedConn); err != nil {
			log.Printf("[Relay/Peering] Failed to route CopyRequest to %s: %v\n", cleanTarget, err)
		}
	}))

	// 6. Cross-gateway ProxyRequest
	router.HandleFunc(string(protocol.TypeProxyRequest), requirePeerAuth("ProxyRequest", func(stream net.Conn, env []byte) {
		var req protocol.ProxyRequest
		if err := json.Unmarshal(env, &req); err != nil {
			stream.Close()
			return
		}

		for _, p := range req.Path {
			if p == r.gatewayID {
				log.Printf("[Relay/Peering] Circular routing loop detected for ProxyRequest path=%v, dropping\n", req.Path)
				stream.Close()
				return
			}
		}

		cleanTarget := r.cleanTargetHostname(req.TargetHostname)
		multiReader := io.MultiReader(strings.NewReader(""), stream)
		prefixedConn := &prefixConn{Conn: stream, r: multiReader}

		if err := r.RouteProxyStream(cleanTarget, env, prefixedConn); err != nil {
			log.Printf("[Relay/Peering] Failed to route ProxyRequest to %s: %v\n", cleanTarget, err)
		}
	}))

	// 7. Cross-gateway DNSQuery
	router.HandleFunc(string(protocol.TypeDNSQuery), requirePeerAuth("DNSQuery", func(stream net.Conn, env []byte) {
		defer stream.Close()
		var query protocol.DNSQuery
		if err := json.Unmarshal(env, &query); err != nil {
			return
		}
		resp := r.ResolveDNS(query, "127.0.0.1")
		respBytes, _ := json.Marshal(resp)
		_, _ = stream.Write(respBytes)
	}))

	err := router.Accept()

	if p := getRegisteredPeer(); p != nil {
		r.unregisterPeerSession(p)
	}

	return err
}

func (r *Relay) cleanTargetHostname(target string) string {
	// If target is thread.gw-id or thread.gw-id.fabric, strip local gateway or domain
	if idx := strings.Index(target, "."); idx > 0 {
		base := target[:idx]
		rest := target[idx+1:]
		if rest == r.gatewayID || rest == r.gatewayID+"."+r.domain || rest == r.domain {
			return base
		}
	}
	return target
}

func (r *Relay) sendLocalThreadAdvertisementsToPeer(peer *GatewayPeerSession) {
	r.mu.RLock()
	localNodes := r.listNodesLocked()
	r.mu.RUnlock()

	if len(localNodes) == 0 {
		return
	}

	var epoch uint64
	var checksum uint32
	if r.reconciler != nil {
		epoch = r.reconciler.Epoch()
		checksum = r.reconciler.ComputeChecksum(localNodes)
	}

	adv := protocol.ThreadAdvertise{
		Type:      protocol.TypeThreadAdvertise,
		GatewayID: r.gatewayID,
		Nodes:     localNodes,
		Epoch:     epoch,
		Checksum:  checksum,
	}
	b, err := json.Marshal(adv)
	if err != nil {
		return
	}

	if peer.Mux != nil && peer.Mux.Session != nil && !peer.Mux.Session.IsClosed() {
		stream, err := peer.Mux.Session.Open()
		if err == nil {
			_, _ = stream.Write(b)
			stream.Close()
		}
	}
}

// BroadcastThreadAdvertise sends thread advertisement to all active peers.
func (r *Relay) BroadcastThreadAdvertise(nodes []protocol.NodeMetadata) {
	r.peerMu.RLock()
	peersList := make([]*GatewayPeerSession, 0, len(r.peers))
	for _, p := range r.peers {
		peersList = append(peersList, p)
	}
	r.peerMu.RUnlock()

	if len(peersList) == 0 || len(nodes) == 0 {
		return
	}

	var epoch uint64
	var checksum uint32
	if r.reconciler != nil {
		epoch = r.reconciler.Epoch()
		r.mu.RLock()
		allLocal := r.listNodesLocked()
		r.mu.RUnlock()
		checksum = r.reconciler.ComputeChecksum(allLocal)
	}

	adv := protocol.ThreadAdvertise{
		Type:      protocol.TypeThreadAdvertise,
		GatewayID: r.gatewayID,
		Nodes:     nodes,
		Epoch:     epoch,
		Checksum:  checksum,
	}
	b, err := json.Marshal(adv)
	if err != nil {
		return
	}

	for _, p := range peersList {
		if p.Mux != nil && p.Mux.Session != nil && !p.Mux.Session.IsClosed() {
			stream, err := p.Mux.Session.Open()
			if err == nil {
				_, _ = stream.Write(b)
				stream.Close()
			}
		}
	}
}

// BroadcastThreadWithdraw sends thread withdrawal notice to all active peers.
func (r *Relay) BroadcastThreadWithdraw(hostname string) {
	r.peerMu.RLock()
	peersList := make([]*GatewayPeerSession, 0, len(r.peers))
	for _, p := range r.peers {
		peersList = append(peersList, p)
	}
	r.peerMu.RUnlock()

	if len(peersList) == 0 || hostname == "" {
		return
	}

	var epoch uint64
	var checksum uint32
	if r.reconciler != nil {
		epoch = r.reconciler.Epoch()
		r.mu.RLock()
		allLocal := r.listNodesLocked()
		r.mu.RUnlock()
		checksum = r.reconciler.ComputeChecksum(allLocal)
	}

	with := protocol.ThreadWithdraw{
		Type:      protocol.TypeThreadWithdraw,
		GatewayID: r.gatewayID,
		Hostname:  hostname,
		Epoch:     epoch,
		Checksum:  checksum,
	}
	b, err := json.Marshal(with)
	if err != nil {
		return
	}

	for _, p := range peersList {
		if p.Mux != nil && p.Mux.Session != nil && !p.Mux.Session.IsClosed() {
			stream, err := p.Mux.Session.Open()
			if err == nil {
				_, _ = stream.Write(b)
				stream.Close()
			}
		}
	}
}
