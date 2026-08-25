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
	"strings"
	"time"

	"fabric/internal/relay"
	"fabric/internal/tlsengine"
)

func main() {
	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	domainFlag := flag.String("domain", defaultDomain, "Domain for the DNS server")
	publicDomainFlag := flag.String("public-domain", os.Getenv("FABRIC_PUBLIC_DOMAIN"), "Public domain for ACME TLS certificates (e.g. example.com)")
	acmeEmailFlag := flag.String("acme-email", os.Getenv("FABRIC_ACME_EMAIL"), "Email address for Let's Encrypt ACME registration")
	acmeStagingFlag := flag.Bool("acme-staging", os.Getenv("FABRIC_ACME_STAGING") == "true", "Use Let's Encrypt staging environment")
	tlsPortFlag := flag.Int("tls-port", 443, "Port for HTTPS/WSS TLS listener")
	httpPortFlag := flag.Int("http-port", 80, "Port for HTTP / ACME HTTP-01 challenge listener")
	caDirFlag := flag.String("ca-dir", "", "Directory to store internal Root CA")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
	}

	// Initialize deep Relay control-plane module
	meshRelay := relay.New(relay.Config{
		Domain:   *domainFlag,
		Token:    token,
		PingFreq: 5 * time.Second,
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
	go func() {
		httpAddr := fmt.Sprintf(":%d", *httpPortFlag)
		srv := &http.Server{
			Addr:    httpAddr,
			Handler: tlsEng.HTTPSRedirectHandler(*tlsPortFlag),
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP] Port %d listener info (run with sudo for port 80): %v", *httpPortFlag, err)
		}
	}()

	// Start Port 443 HTTPS / WSS Server (Dynamic Dual-Mode SNI)
	go func() {
		tlsAddr := fmt.Sprintf(":%d", *tlsPortFlag)
		tlsLn, err := net.Listen("tcp", tlsAddr)
		if err != nil {
			log.Printf("[TLS] Port %d listener info (run with sudo for port 443): %v", *tlsPortFlag, err)
			return
		}
		defer tlsLn.Close()
		log.Printf("[TLS] Socket TLS listening on %s (HTTPS / WSS with Dual-Mode SNI)", tlsAddr)

		secureSrv := &http.Server{
			Handler: http.DefaultServeMux,
		}
		secureLn := tls.NewListener(tlsLn, tlsEng.TLSConfig())
		if err := secureSrv.Serve(secureLn); err != nil && err != http.ErrServerClosed {
			log.Printf("[TLS] Server error on %s: %v", tlsAddr, err)
		}
	}()

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
				log.Printf("[Relay] Session ended for %s: %v\n", r.RemoteAddr, err)
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

	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "2.3.1",
			"domain":  *domainFlag,
			"role":    "socket",
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

	log.Println("Socket listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
