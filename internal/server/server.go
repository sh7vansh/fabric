package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/relay"
	"fabric/internal/tlsengine"
	"fabric/internal/version"
	"fabric/internal/wireguard"
)

// Config configures the deep Server control-plane module.
type Config struct {
	Port              int
	Domain            string
	PublicDomain      string
	ACMEEmail         string
	ACMEStaging       bool
	HTTPPort          int
	CADir             string
	Token             string
	AdminToken        string
	ServerID          string
	GatewayID         string
	Region            string
	FederationCA      string
	Peers             []string
	LeafOf            string
	WireGuardPort     int
	WireGuardSubnet   string
	WireGuardDisabled bool
	WireGuardKeyPath  string
	WireGuardDevices  string
	WireGuardEndpoint string
}

// SecureServer is the deep control-plane domain module encapsulating MeshRelay,
// dynamic Dual-Mode TLS Engine, WireGuardEngine, and authenticated TLS WebSocket multiplexing.
type SecureServer struct {
	cfg        Config
	relay      *relay.Relay
	tlsEngine  *tlsengine.Engine
	accessCtrl *AccessController
	wgEngine   *wireguard.WireGuardEngine
	ipam       *wireguard.IPAMManager
	mux        *http.ServeMux
	mu         sync.RWMutex
	boundAddr  string
	closeCh    chan struct{}
	closed     bool
}

// Server is a backward-compatible alias for SecureServer.
type Server = SecureServer

// NewSecureServer constructs and initializes a new deep SecureServer module.
func NewSecureServer(cfg Config) (*SecureServer, error) {
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

	ipam, err := wireguard.NewIPAMManager(cfg.WireGuardSubnet)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPAM: %w", err)
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
		OnNodeRegistered: func(meta protocol.NodeMetadata) {
			_, _ = ipam.AllocateThreadIP(meta.Hostname)
		},
		OnNodeUnregistered: func(hostname string) {
			ipam.ReleaseThreadIP(hostname)
		},
	})

	tlsEng, err := tlsengine.New(tlsengine.Config{
		CADir:        cfg.CADir,
		MeshDomain:   cfg.Domain,
		PublicDomain: cfg.PublicDomain,
		ACMEEmail:    cfg.ACMEEmail,
		ACMEStaging:  cfg.ACMEStaging,
		ActiveThreads: func() []string {
			threads := meshRelay.ListThreads()
			list := make([]string, len(threads))
			for i, t := range threads {
				list[i] = t.Hostname
			}
			return list
		},
	})
	if err != nil {
		meshRelay.Close()
		return nil, fmt.Errorf("failed to initialize TLS engine: %w", err)
	}

	if ca := tlsEng.CA(); ca != nil && len(ca.CertPEM()) > 0 {
		if os.Geteuid() == 0 {
			_ = os.MkdirAll("/etc/fabric", 0755)
			_ = os.WriteFile("/etc/fabric/ca.crt", ca.CertPEM(), 0644)
			_ = os.MkdirAll("/etc/fabric/ca", 0755)
			_ = os.WriteFile("/etc/fabric/ca/ca.crt", ca.CertPEM(), 0644)
		}
		if home, err := os.UserHomeDir(); err == nil {
			userFabricDir := filepath.Join(home, ".fabric")
			_ = os.MkdirAll(userFabricDir, 0755)
			_ = os.WriteFile(filepath.Join(userFabricDir, "ca.crt"), ca.CertPEM(), 0644)
		}
	}

	accessCtrl := NewAccessController(AccessControllerConfig{
		ClusterToken: cfg.Token,
		AdminToken:   cfg.AdminToken,
	})

	var wgEng *wireguard.WireGuardEngine
	if !cfg.WireGuardDisabled {
		wgPort := cfg.WireGuardPort
		if wgPort <= 0 {
			wgPort = 51820
		}
		var err error
		wgEng, err = wireguard.NewEngine(wireguard.EngineConfig{
			Port:         wgPort,
			Subnet:       cfg.WireGuardSubnet,
			KeyPath:      cfg.WireGuardKeyPath,
			DevicesPath:  cfg.WireGuardDevices,
			MeshDomain:   cfg.Domain,
			EndpointHost: cfg.WireGuardEndpoint,
		}, ipam, nil, meshRelay)
		if err != nil {
			log.Printf("[Server] Warning: Failed to start WireGuard engine: %v\n", err)
		}
	}

	s := &SecureServer{
		cfg:        cfg,
		relay:      meshRelay,
		tlsEngine:  tlsEng,
		accessCtrl: accessCtrl,
		wgEngine:   wgEng,
		ipam:       ipam,
		mux:        http.NewServeMux(),
		closeCh:    make(chan struct{}),
	}

	s.registerRoutes()
	return s, nil
}

// New constructs and initializes a new deep Server module (alias for NewSecureServer).
func New(cfg Config) (*SecureServer, error) {
	return NewSecureServer(cfg)
}

// Relay returns the underlying Relay module.
func (s *Server) Relay() *relay.Relay {
	return s.relay
}

// TLSEngine returns the attached Dual-Mode TLS Engine.
func (s *Server) TLSEngine() *tlsengine.Engine {
	return s.tlsEngine
}

// AccessController returns the attached AccessController module.
func (s *Server) AccessController() *AccessController {
	return s.accessCtrl
}

// WireGuardEngine returns the attached userspace WireGuard engine.
func (s *Server) WireGuardEngine() *wireguard.WireGuardEngine {
	return s.wgEngine
}

// IPAM returns the attached IPAM overlay manager.
func (s *Server) IPAM() *wireguard.IPAMManager {
	return s.ipam
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

	// Primary WebSocket endpoint for Thread daemons and CLI clients (Pre-upgrade auth & rate-limiting)
	s.mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ident, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect)
		if err != nil {
			http.Error(w, err.Error(), code)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("[Server] Upgrade error:", err)
			return
		}

		go func() {
			if err := s.relay.ServeWSAuth(conn, r.RemoteAddr, true); err != nil {
				log.Printf("[Server] Session ended for %s (%s): %v\n", r.RemoteAddr, ident.Role, err)
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
			_, code, err := s.accessCtrl.AuthenticateRequest(r)
			if err != nil {
				http.Error(w, err.Error(), code)
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
		resp := map[string]interface{}{
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
		}
		if s.wgEngine != nil {
			resp["wireguard_port"] = s.wgEngine.ListenPort()
			resp["wireguard_public_key"] = s.wgEngine.ServerPublicKey()
		}
		json.NewEncoder(w).Encode(resp)
	})

	threadsListHandler := func(w http.ResponseWriter, r *http.Request) {
		if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect); err != nil {
			http.Error(w, err.Error(), code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.relay.ListNodes())
	}

	threadsGetHandler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect); err != nil {
				http.Error(w, err.Error(), code)
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
			if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect); err != nil {
				http.Error(w, err.Error(), code)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.relay.ListPeers())
			return
		}
		if r.Method == http.MethodPost {
			if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityAdmin); err != nil {
				http.Error(w, err.Error(), code)
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
			if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect); err != nil {
				http.Error(w, err.Error(), code)
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
			if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityAdmin); err != nil {
				http.Error(w, err.Error(), code)
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

	// Device Management Endpoints
	devicesListHandler := func(w http.ResponseWriter, r *http.Request) {
		if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect); err != nil {
			http.Error(w, err.Error(), code)
			return
		}
		if s.wgEngine == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]wireguard.DeviceEntry{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.wgEngine.ListDevices())
	}

	devicesPostHandler := func(w http.ResponseWriter, r *http.Request) {
		if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityAdmin); err != nil {
			http.Error(w, err.Error(), code)
			return
		}
		if s.wgEngine == nil {
			http.Error(w, "WireGuard engine is not enabled on this Server", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			Name         string `json:"name"`
			PublicKey    string `json:"public_key"`
			PresharedKey string `json:"preshared_key,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.PublicKey == "" {
			http.Error(w, "invalid request body: missing name or public_key", http.StatusBadRequest)
			return
		}

		dev, err := s.wgEngine.AddDevice(body.Name, body.PublicKey, body.PresharedKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		endpoint := s.cfg.WireGuardEndpoint
		if endpoint == "" {
			host := "localhost"
			if s.cfg.PublicDomain != "" {
				host = s.cfg.PublicDomain
			} else if reqHost, _, err := net.SplitHostPort(r.Host); err == nil && reqHost != "" {
				host = reqHost
			} else if r.Host != "" {
				host = r.Host
			}
			endpoint = fmt.Sprintf("%s:%d", host, s.wgEngine.ListenPort())
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":              dev.Name,
			"public_key":        dev.PublicKey,
			"preshared_key":     dev.PresharedKey,
			"virtual_ip":        dev.VirtualIP,
			"allowed_ips":       []string{"100.64.0.0/10"},
			"dns":               s.ipam.ServerIP().String(),
			"server_public_key": s.wgEngine.ServerPublicKey(),
			"server_endpoint":   endpoint,
			"created_at":        dev.CreatedAt,
		})
	}

	deviceDetailHandler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.URL.Path[len(prefix):]
			if r.Method == http.MethodGet {
				if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityInspect); err != nil {
					http.Error(w, err.Error(), code)
					return
				}
				if s.wgEngine == nil {
					http.Error(w, "WireGuard engine is not enabled on this Server", http.StatusServiceUnavailable)
					return
				}
				dev, ok := s.wgEngine.Store().Get(name)
				if !ok {
					http.Error(w, "device not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dev)
				return
			}
			if r.Method == http.MethodDelete {
				if _, code, err := s.accessCtrl.AuthenticateRequest(r, CapabilityAdmin); err != nil {
					http.Error(w, err.Error(), code)
					return
				}
				if s.wgEngine == nil {
					http.Error(w, "WireGuard engine is not enabled on this Server", http.StatusServiceUnavailable)
					return
				}
				if err := s.wgEngine.RemoveDevice(name); err != nil {
					http.Error(w, err.Error(), http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "removed",
					"device": name,
				})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}

	deviceRoute := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			devicesListHandler(w, r)
		} else if r.Method == http.MethodPost {
			devicesPostHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}

	s.mux.HandleFunc("/devices", deviceRoute)
	s.mux.HandleFunc("/api/v1/devices", deviceRoute)
	s.mux.HandleFunc("/devices/", deviceDetailHandler("/devices/"))
	s.mux.HandleFunc("/api/v1/devices/", deviceDetailHandler("/api/v1/devices/"))
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
	if s.wgEngine != nil {
		_ = s.wgEngine.Close()
	}
	if s.accessCtrl != nil {
		s.accessCtrl.Close()
	}
	if s.relay != nil {
		s.relay.Close()
	}
	return nil
}
