package tlsengine

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"fabric/internal/pki"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config configures the Dual-Mode TLS Engine.
type Config struct {
	CADir          string
	MeshDomain     string
	PublicDomain   string
	ACMEEmail      string
	ACMECacheDir   string
	ACMEStaging    bool
	AllowedHosts   []string
	ActiveNodes    func() []string
}

// Engine unifies in-process Root CA certificate minting with Let's Encrypt ACME autocert.
type Engine struct {
	mu           sync.RWMutex
	ca           *pki.CA
	acmeManager  *autocert.Manager
	meshDomain   string
	publicDomain string
	activeNodes  func() []string
	allowedHosts map[string]struct{}
}

// New creates and initializes a new dual-mode TLS engine.
func New(cfg Config) (*Engine, error) {
	if cfg.MeshDomain == "" {
		cfg.MeshDomain = "fabric.mesh"
	}

	caDir := cfg.CADir
	if caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			caDir = "/tmp/fabric-ca"
		} else {
			caDir = filepath.Join(home, ".fabric", "ca")
		}
	}

	ca, err := pki.LoadOrInitCA(caDir, cfg.MeshDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to init internal CA: %w", err)
	}

	engine := &Engine{
		ca:           ca,
		meshDomain:   strings.ToLower(strings.TrimSpace(cfg.MeshDomain)),
		publicDomain: strings.ToLower(strings.TrimSpace(cfg.PublicDomain)),
		activeNodes:  cfg.ActiveNodes,
		allowedHosts: make(map[string]struct{}),
	}

	for _, h := range cfg.AllowedHosts {
		engine.allowedHosts[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}

	if engine.publicDomain != "" {
		cacheDir := cfg.ACMECacheDir
		if cacheDir == "" {
			home, _ := os.UserHomeDir()
			cacheDir = filepath.Join(home, ".fabric", "acme-cache")
		}
		if cfg.ACMEStaging {
			cacheDir = filepath.Join(cacheDir, "staging")
		}
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create acme cache directory: %w", err)
		}

		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: engine.acmeHostPolicy,
			Cache:      autocert.DirCache(cacheDir),
			Email:      cfg.ACMEEmail,
		}

		if cfg.ACMEStaging {
			mgr.Client = &acme.Client{
				DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			}
		}

		engine.acmeManager = mgr
		log.Printf("[TLS] ACME Autocert initialized for public domain: %s (staging=%v)", engine.publicDomain, cfg.ACMEStaging)
	}

	return engine, nil
}

// CA returns the underlying internal Certificate Authority.
func (e *Engine) CA() *pki.CA {
	return e.ca
}

// ACMEManager returns the autocert Manager, if configured.
func (e *Engine) ACMEManager() *autocert.Manager {
	return e.acmeManager
}

func (e *Engine) matchesPublicDomain(host string) bool {
	if e.publicDomain == "" {
		return false
	}
	return host == e.publicDomain || strings.HasSuffix(host, "."+e.publicDomain)
}

func (e *Engine) isInternalOrLocal(host string) bool {
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return true
	}
	if strings.HasSuffix(host, ".mesh") {
		return true
	}
	if e.meshDomain != "" && (host == e.meshDomain || strings.HasSuffix(host, "."+e.meshDomain)) {
		return true
	}
	return false
}

func (e *Engine) acmeHostPolicy(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Never send internal mesh or local hostnames to ACME
	if e.isInternalOrLocal(host) {
		return fmt.Errorf("acme: internal or local hostname %q disallowed", host)
	}

	if e.matchesPublicDomain(host) {
		if host == e.publicDomain {
			return nil
		}

		// Validate subdomains
		sub := strings.TrimSuffix(host, "."+e.publicDomain)
		if e.activeNodes != nil {
			for _, n := range e.activeNodes() {
				if strings.EqualFold(n, sub) {
					return nil
				}
			}
		}
	}

	e.mu.RLock()
	_, allowed := e.allowedHosts[host]
	e.mu.RUnlock()
	if allowed {
		return nil
	}

	return fmt.Errorf("acme: host %q not authorized by host policy", host)
}

// GetCertificate implements dynamic SNI routing between internal CA and ACME autocert.
func (e *Engine) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if h, _, err := net.SplitHostPort(serverName); err == nil {
		serverName = h
	}

	// 1. If serverName is empty, localhost, IP address, or ends with .mesh / meshDomain:
	if e.isInternalOrLocal(serverName) {
		return e.ca.GetCertificate(hello)
	}

	// 2. If ACME is configured and hostname matches public domain:
	if e.acmeManager != nil && e.matchesPublicDomain(serverName) {
		return e.acmeManager.GetCertificate(hello)
	}

	// 3. Fallback to Internal CA minting
	return e.ca.GetCertificate(hello)
}

// TLSConfig returns a server tls.Config backed by this dual-mode engine.
func (e *Engine) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: e.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// HTTPHandler wraps a fallback HTTP handler with ACME HTTP-01 challenge support.
func (e *Engine) HTTPHandler(fallback http.Handler) http.Handler {
	if e.acmeManager != nil {
		return e.acmeManager.HTTPHandler(fallback)
	}
	return fallback
}

// HTTPSRedirectHandler creates an HTTP handler that redirects all non-ACME requests to HTTPS.
func (e *Engine) HTTPSRedirectHandler(httpsPort int) http.Handler {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHost := r.Host
		if h, _, err := net.SplitHostPort(targetHost); err == nil {
			targetHost = h
		}
		if httpsPort != 443 && httpsPort > 0 {
			targetHost = fmt.Sprintf("%s:%d", targetHost, httpsPort)
		}

		targetURL := "https://" + targetHost + r.URL.RequestURI()
		http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
	})

	return e.HTTPHandler(redirect)
}
