package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fabric/internal/pki"
	"fabric/internal/relay"
	"fabric/internal/tlsengine"
	"fabric/internal/version"
)

// Config configures the deep Server control-plane module.
type Config struct {
	Port         int
	Domain       string
	PublicDomain string
	ACMEEmail    string
	ACMEStaging  bool
	HTTPPort     int
	CADir        string
	Token        string
	AdminToken   string
	ServerID     string
	GatewayID    string
	Region       string
	FederationCA string
	Peers        []string
	LeafOf       string
}

// Server is the deep control-plane domain module encapsulating MeshRelay,
// dynamic Dual-Mode TLS Engine, and authenticated TLS WebSocket multiplexing.
type Server struct {
	cfg       Config
	relay     *relay.Relay
	tlsEngine *tlsengine.Engine
	mux       *http.ServeMux
	mu        sync.RWMutex
	boundAddr string
	closeCh   chan struct{}
	closed    bool
}

// New constructs and initializes a new deep Server module.
func New(cfg Config) (*Server, error) {
	if cfg.Domain == "" {
		cfg.Domain = "fabric.mesh"
	}
	if cfg.Port <= 0 {
		cfg.Port = 8443
	}

	serverID := cfg.ServerID
	if serverID == "" {
		serverID = cfg.GatewayID
	}

	meshRelay := relay.New(relay.Config{
		Domain:       cfg.Domain,
		Token:        cfg.Token,
		AdminToken:   cfg.AdminToken,
		PingFreq:     5 * time.Second,
		ServerID:     serverID,
		GatewayID:    serverID,
		Region:       cfg.Region,
		FederationCA: cfg.FederationCA,
		Peers:        cfg.Peers,
		LeafOf:       cfg.LeafOf,
	})

	tlsEng, err := tlsengine.New(tlsengine.Config{
		CADir:        cfg.CADir,
		MeshDomain:   cfg.Domain,
		PublicDomain: cfg.PublicDomain,
		ACMEEmail:    cfg.ACMEEmail,
		ACMEStaging:  cfg.ACMEStaging,
		ActiveNodes: func() []string {
			nodes := meshRelay.ListNodes()
			list := make([]string, len(nodes))
			for i, n := range nodes {
				list[i] = n.Hostname
			}
			return list
		},
	})
	if err != nil {
		meshRelay.Close()
		return nil, fmt.Errorf("failed to initialize TLS engine: %w", err)
	}

	s := &Server{
		cfg:       cfg,
		relay:     meshRelay,
		tlsEngine: tlsEng,
		mux:       http.NewServeMux(),
		closeCh:   make(chan struct{}),
	}

	s.registerRoutes()
	return s, nil
}

// Relay returns the underlying Relay module.
func (s *Server) Relay() *relay.Relay {
	return s.relay
}

// TLSEngine returns the attached Dual-Mode TLS Engine.
func (s *Server) TLSEngine() *tlsengine.Engine {
	return s.tlsEngine
}

// Handler returns the HTTP handler with all registered endpoints.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Addr returns the actual bound listener address once serving.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.boundAddr
}

func (s *Server) registerRoutes() {
	upgrader := s.relay.Upgrader()

	extractBearerToken := func(r *http.Request) string {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return ""
	}

	authenticate := func(w http.ResponseWriter, r *http.Request) bool {
		provided := extractBearerToken(r)
		if !s.relay.ValidateToken(provided) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}

	authenticateAdmin := func(w http.ResponseWriter, r *http.Request) bool {
		provided := extractBearerToken(r)
		if !s.relay.ValidateAdminToken(provided) {
			http.Error(w, "Unauthorized: Admin token required", http.StatusUnauthorized)
			return false
		}
		return true
	}

	// Primary WebSocket endpoint for Thread daemons and CLI clients
	s.mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		provided := extractBearerToken(r)
		authenticated := s.relay.ValidateToken(provided)

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("[Server] Upgrade error:", err)
			return
		}

		go func() {
			if err := s.relay.ServeWSAuth(conn, r.RemoteAddr, authenticated); err != nil {
				log.Printf("[Server] Session ended for %s: %v\n", r.RemoteAddr, err)
			}
		}()
	})

	peerHandler := func(w http.ResponseWriter, r *http.Request) {
		if s.relay.FederationCA() != "" {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "Unauthorized: mTLS Federation Certificate Required", http.StatusUnauthorized)
				return
			}
			_, err := pki.ExtractGatewayID(r.TLS.PeerCertificates[0])
			if err != nil {
				http.Error(w, "Unauthorized: Invalid Federation Certificate: "+err.Error(), http.StatusUnauthorized)
				return
			}
		} else {
			provided := extractBearerToken(r)
			if !s.relay.ValidateToken(provided) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		isLeaf := r.URL.Query().Get("leaf") == "true"
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("[Server/Peering] Peer upgrade error:", err)
			return
		}

		go func() {
			if err := s.relay.ServePeerWS(conn, r.RemoteAddr, isLeaf); err != nil {
				log.Printf("[Server/Peering] Peer session ended for %s: %v\n", r.RemoteAddr, err)
			}
		}()
	}

	// Canonical & legacy Yamux inter-server federation peering endpoints
	s.mux.HandleFunc("/peer", peerHandler)
	s.mux.HandleFunc("/gateway/v1/peer", peerHandler)

	s.mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		bInfo := version.GetBuildInfo()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":          bInfo.Version,
			"git_commit":       bInfo.GitCommit,
			"build_date":       bInfo.BuildDate,
			"go_version":       bInfo.GoVersion,
			"protocol_version": bInfo.ProtocolVersion,
			"domain":           s.cfg.Domain,
			"role":             "server",
			"gateway_id":       s.relay.GatewayID(),
			"server_id":        s.relay.ServerID(),
			"region":           s.relay.Region(),
		})
	})

	threadsListHandler := func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.relay.ListNodes())
	}

	threadsGetHandler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !authenticate(w, r) {
				return
			}
			hostname := r.URL.Path[len(prefix):]
			meta, ok := s.relay.GetNode(hostname)
			if !ok {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta)
		}
	}

	// Canonical Thread endpoints & legacy node aliases
	s.mux.HandleFunc("/threads", threadsListHandler)
	s.mux.HandleFunc("/threads/", threadsGetHandler("/threads/"))
	s.mux.HandleFunc("/nodes", threadsListHandler)
	s.mux.HandleFunc("/nodes/", threadsGetHandler("/nodes/"))

	s.mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !authenticate(w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.relay.ListPeers())
			return
		}
		if r.Method == http.MethodPost {
			if !authenticateAdmin(w, r) {
				return
			}
			var body struct {
				Endpoint string `json:"endpoint"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Endpoint == "" {
				http.Error(w, "invalid request body: missing endpoint", http.StatusBadRequest)
				return
			}
			if err := s.relay.AddPeer(body.Endpoint); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "initiating connection", "endpoint": body.Endpoint})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	s.mux.HandleFunc("/peers/", func(w http.ResponseWriter, r *http.Request) {
		peerID := r.URL.Path[len("/peers/"):]
		if r.Method == http.MethodGet {
			if !authenticate(w, r) {
				return
			}
			info, ok := s.relay.GetPeer(peerID)
			if !ok {
				http.Error(w, "Peer not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info)
			return
		}
		if r.Method == http.MethodDelete {
			if !authenticateAdmin(w, r) {
				return
			}
			if err := s.relay.RemovePeer(peerID); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "removed", "gateway_id": peerID})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
}

// TLSConfig returns the unified *tls.Config for securing server listeners.
func (s *Server) TLSConfig() *tls.Config {
	tlsCfg := s.tlsEngine.TLSConfig()
	if s.cfg.FederationCA != "" {
		if caPool, err := pki.LoadFederationCertPool(s.cfg.FederationCA); err == nil {
			tlsCfg.ClientCAs = caPool
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return tlsCfg
}

// ServeTLS runs the server on an existing net.Listener with automatic TLS encryption.
func (s *Server) ServeTLS(ln net.Listener) error {
	tlsLn := tls.NewListener(ln, s.TLSConfig())
	defer tlsLn.Close()

	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()

	srv := &http.Server{
		Handler: s.mux,
	}

	go func() {
		<-s.closeCh
		_ = srv.Close()
	}()

	return srv.Serve(tlsLn)
}

// Run executes the complete Server lifecycle, binding TLS listeners and handling ACME/HTTP redirects.
func (s *Server) Run(ctx context.Context) error {
	defer s.Close()

	// 1. Start Port 80 HTTP redirector (ACME HTTP-01 + 301 HTTPS redirects only)
	if s.cfg.HTTPPort > 0 {
		go func() {
			httpAddr := fmt.Sprintf(":%d", s.cfg.HTTPPort)
			srv := &http.Server{
				Addr:    httpAddr,
				Handler: s.tlsEngine.HTTPSRedirectHandler(s.cfg.Port),
			}
			go func() {
				<-ctx.Done()
				_ = srv.Close()
			}()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[HTTP] Port %d redirect listener info: %v", s.cfg.HTTPPort, err)
			}
		}()
	}

	// 2. Start primary TLS Server Listener (Default :8443 or :443)
	primaryAddr := fmt.Sprintf(":%d", s.cfg.Port)
	ln, err := net.Listen("tcp", primaryAddr)
	if err != nil {
		return fmt.Errorf("failed to bind server listener on %s: %w", primaryAddr, err)
	}
	defer ln.Close()

	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()

	log.Printf("[Server] Fabric Server TLS listening on %s (WSS / HTTPS with Auto-TLS)", s.boundAddr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ServeTLS(ln)
	}()

	select {
	case <-ctx.Done():
		s.Close()
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Close gracefully terminates the server and relay resources.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	if s.relay != nil {
		s.relay.Close()
	}
	return nil
}
