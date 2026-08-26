package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fabric/internal/pki"
	"fabric/internal/relay"
	"fabric/internal/tlsengine"
	"fabric/internal/version"
)

func main() {
	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	portEnv := os.Getenv("FABRIC_PORT")
	defaultPort := 8080
	if portEnv != "" {
		if p, err := strconv.Atoi(portEnv); err == nil {
			defaultPort = p
		}
	}

	portFlag := flag.Int("port", defaultPort, "Port for HTTP / WebSocket listener")
	domainFlag := flag.String("domain", defaultDomain, "Domain for the Fabric DNS server")
	publicDomainFlag := flag.String("public-domain", os.Getenv("FABRIC_PUBLIC_DOMAIN"), "Public domain for ACME TLS certificates (e.g. example.com)")
	acmeEmailFlag := flag.String("acme-email", os.Getenv("FABRIC_ACME_EMAIL"), "Email address for Let's Encrypt ACME registration")
	acmeStagingFlag := flag.Bool("acme-staging", os.Getenv("FABRIC_ACME_STAGING") == "true", "Use Let's Encrypt staging environment")
	tlsPortFlag := flag.Int("tls-port", 443, "Port for HTTPS/WSS TLS listener (0 to disable)")
	httpPortFlag := flag.Int("http-port", 80, "Port for HTTP / ACME HTTP-01 challenge listener (0 to disable)")
	caDirFlag := flag.String("ca-dir", "", "Directory to store internal Root CA")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	adminTokenFlag := flag.String("admin-token", os.Getenv("FABRIC_ADMIN_TOKEN"), "Pre-shared token for administrative control plane operations (defaults to token)")
	gatewayIDFlag := flag.String("gateway-id", os.Getenv("FABRIC_GATEWAY_ID"), "Unique gateway identifier for federation")
	regionFlag := flag.String("region", os.Getenv("FABRIC_REGION"), "Geographic region for this gateway (e.g. us-east, eu-west)")
	federationCAFlag := flag.String("federation-ca", os.Getenv("FABRIC_FEDERATION_CA"), "Path to shared Federation Root CA certificate")
	peerFlag := flag.String("peer", os.Getenv("FABRIC_PEERS"), "Comma-separated list of peer gateway URLs to connect to")
	leafOfFlag := flag.String("leaf-of", os.Getenv("FABRIC_LEAF_OF"), "Core gateway URL to connect to as an outbound Leaf relay")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
	}

	var initialPeers []string
	if *peerFlag != "" {
		for _, p := range strings.Split(*peerFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				initialPeers = append(initialPeers, p)
			}
		}
	}

	// Initialize Relay control-plane module
	meshRelay := relay.New(relay.Config{
		Domain:       *domainFlag,
		Token:        token,
		AdminToken:   *adminTokenFlag,
		PingFreq:     5 * time.Second,
		GatewayID:    *gatewayIDFlag,
		Region:       *regionFlag,
		FederationCA: *federationCAFlag,
		Peers:        initialPeers,
		LeafOf:       *leafOfFlag,
	})
	defer meshRelay.Close()

	// Initialize Dual-Mode TLS Engine (Internal CA + ACME Autocert)
	tlsEng, err := tlsengine.New(tlsengine.Config{
		CADir:        *caDirFlag,
		MeshDomain:   *domainFlag,
		PublicDomain: *publicDomainFlag,
		ACMEEmail:    *acmeEmailFlag,
		ACMEStaging:  *acmeStagingFlag,
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
		log.Fatalf("Failed to initialize TLS engine: %v", err)
	}

	// Start Port 80 HTTP Server (ACME Challenges + 301 HTTPS Redirects)
	if *httpPortFlag > 0 {
		go func() {
			httpAddr := fmt.Sprintf(":%d", *httpPortFlag)
			srv := &http.Server{
				Addr:    httpAddr,
				Handler: tlsEng.HTTPSRedirectHandler(*tlsPortFlag),
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[HTTP] Port %d listener info: %v", *httpPortFlag, err)
			}
		}()
	}

	// Start HTTPS / WSS Server (Dynamic Dual-Mode SNI)
	if *tlsPortFlag > 0 {
		go func() {
			tlsAddr := fmt.Sprintf(":%d", *tlsPortFlag)
			tlsLn, err := net.Listen("tcp", tlsAddr)
			if err != nil {
				log.Printf("[TLS] Port %d listener info: %v", *tlsPortFlag, err)
				return
			}
			defer tlsLn.Close()
			log.Printf("[TLS] Fabric Server TLS listening on %s (HTTPS / WSS with Dual-Mode SNI)", tlsAddr)

			secureSrv := &http.Server{
				Handler: http.DefaultServeMux,
			}
			tlsCfg := tlsEng.TLSConfig()
			if *federationCAFlag != "" {
				caPool, err := pki.LoadFederationCertPool(*federationCAFlag)
				if err != nil {
					log.Fatalf("Failed to load federation CA: %v", err)
				}
				tlsCfg.ClientCAs = caPool
				tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
			secureLn := tls.NewListener(tlsLn, tlsCfg)
			if err := secureSrv.Serve(secureLn); err != nil && err != http.ErrServerClosed {
				log.Printf("[TLS] Server error on %s: %v", tlsAddr, err)
			}
		}()
	}

	upgrader := meshRelay.Upgrader()

	extractBearerToken := func(r *http.Request) string {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return ""
	}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		provided := extractBearerToken(r)
		authenticated := meshRelay.ValidateToken(provided)

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Upgrade error:", err)
			return
		}

		go func() {
			if err := meshRelay.ServeWSAuth(conn, r.RemoteAddr, authenticated); err != nil {
				log.Printf("[Server] Session ended for %s: %v\n", r.RemoteAddr, err)
			}
		}()
	})

	// /gateway/v1/peer WebSocket endpoint for inter-server Yamux peering
	http.HandleFunc("/gateway/v1/peer", func(w http.ResponseWriter, r *http.Request) {
		if meshRelay.FederationCA() != "" {
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
			if !meshRelay.ValidateToken(provided) {
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
			if err := meshRelay.ServePeerWS(conn, r.RemoteAddr, isLeaf); err != nil {
				log.Printf("[Server/Peering] Peer session ended for %s: %v\n", r.RemoteAddr, err)
			}
		}()
	})

	authenticate := func(w http.ResponseWriter, r *http.Request) bool {
		provided := extractBearerToken(r)
		if !meshRelay.ValidateToken(provided) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}

	authenticateAdmin := func(w http.ResponseWriter, r *http.Request) bool {
		provided := extractBearerToken(r)
		if !meshRelay.ValidateAdminToken(provided) {
			http.Error(w, "Unauthorized: Admin token required", http.StatusUnauthorized)
			return false
		}
		return true
	}

	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		bInfo := version.GetBuildInfo()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":          bInfo.Version,
			"git_commit":       bInfo.GitCommit,
			"build_date":       bInfo.BuildDate,
			"go_version":       bInfo.GoVersion,
			"protocol_version": bInfo.ProtocolVersion,
			"domain":           *domainFlag,
			"role":             "server",
			"gateway_id":       meshRelay.GatewayID(),
			"server_id":        meshRelay.ServerID(),
			"region":           meshRelay.Region(),
		})
	})

	http.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meshRelay.ListNodes())
	})

	http.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}
		hostname := r.URL.Path[len("/nodes/"):]
		meta, ok := meshRelay.GetNode(hostname)
		if !ok {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})

	http.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !authenticate(w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meshRelay.ListPeers())
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
			if err := meshRelay.AddPeer(body.Endpoint); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "initiating connection", "endpoint": body.Endpoint})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	http.HandleFunc("/peers/", func(w http.ResponseWriter, r *http.Request) {
		peerID := r.URL.Path[len("/peers/"):]
		if r.Method == http.MethodGet {
			if !authenticate(w, r) {
				return
			}
			info, ok := meshRelay.GetPeer(peerID)
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
			if err := meshRelay.RemovePeer(peerID); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "removed", "gateway_id": peerID})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	log.Printf("Fabric Server listening on :%d\n", *portFlag)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *portFlag), nil))
}
