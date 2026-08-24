package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func loadKeyPair(dir string) (*tls.Certificate, error) {
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// BuildMTLSConfig constructs a tls.Config with system root CAs and discovers local cluster certificates.
func BuildMTLSConfig(customCAPath string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	// 1. Explicit user-provided CA
	if customCAPath != "" {
		pemBytes, err := os.ReadFile(customCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read custom CA file %s: %w", customCAPath, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid certificates found in %s", customCAPath)
		}
	}

	// 2. Discover default cluster CA locations if not already present
	defaultPaths := []string{
		"/etc/fabric/ca/ca.crt",
		"/etc/fabric/ca.crt",
	}
	if home, err := os.UserHomeDir(); err == nil {
		defaultPaths = append(defaultPaths,
			filepath.Join(home, ".fabric", "ca", "ca.crt"),
			filepath.Join(home, ".fabric", "ca.crt"),
		)
	}

	for _, p := range defaultPaths {
		if p == customCAPath {
			continue
		}
		if pemBytes, err := os.ReadFile(p); err == nil && len(pemBytes) > 0 {
			pool.AppendCertsFromPEM(pemBytes)
		}
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	// 3. Opportunistically load client/node certificate for mTLS if it exists
	var candidateDirs []string
	if customCAPath != "" {
		candidateDirs = append(candidateDirs, filepath.Dir(customCAPath))
	}
	for _, p := range defaultPaths {
		candidateDirs = append(candidateDirs, filepath.Dir(p))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidateDirs = append(candidateDirs, filepath.Join(home, ".fabric"))
	}

	for _, dir := range candidateDirs {
		if cert, err := loadKeyPair(dir); err == nil {
			tlsCfg.Certificates = append(tlsCfg.Certificates, *cert)
			break
		}
	}

	// 4. Auto-heal: If no client certificate was loaded, but a CA private key exists locally,
	// auto-mint a client certificate and attach it.
	if len(tlsCfg.Certificates) == 0 {
		for _, dir := range candidateDirs {
			if fileExists(filepath.Join(dir, "ca.crt")) && fileExists(filepath.Join(dir, "ca.key")) {
				if ca, err := LoadOrInitCA(dir, "fabric.mesh"); err == nil && ca != nil {
					_ = ca.EnsureClientCertificate(dir)
					if home, err := os.UserHomeDir(); err == nil {
						_ = ca.EnsureClientCertificate(filepath.Join(home, ".fabric"))
					}
					if cert, err := loadKeyPair(dir); err == nil {
						tlsCfg.Certificates = append(tlsCfg.Certificates, *cert)
						break
					}
				}
			}
		}
	}

	return tlsCfg, nil
}

// NewWSSDialer constructs a websocket.Dialer configured with cluster root CAs and custom CA support.
func NewWSSDialer(customCAPath string) (*websocket.Dialer, error) {
	tlsCfg, err := BuildMTLSConfig(customCAPath)
	if err != nil {
		return nil, err
	}
	return &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig:  tlsCfg,
	}, nil
}

// NormalizeURL auto-upgrades schemes for TLS ports (e.g. port 443).
func NormalizeURL(rawURL string) (*url.URL, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "ws://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	// Auto-upgrade ws -> wss if port is 443 or host is https
	if u.Scheme == "ws" {
		if u.Port() == "443" || u.Port() == "8443" {
			u.Scheme = "wss"
		}
	} else if u.Scheme == "http" {
		if u.Port() == "443" || u.Port() == "8443" {
			u.Scheme = "https"
		}
	}

	return u, nil
}

// FormatTLSError wraps a TLS handshake error with actionable diagnostic guidance.
func FormatTLSError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	if strings.Contains(errStr, "certificate signed by unknown authority") ||
		strings.Contains(errStr, "x509: certificate signed by unknown authority") {
		return fmt.Errorf("%w\n  👉 Tip: The socket is using a private Root CA. Run 'fabric setup --trust-ca' or pass '--ca-cert /path/to/ca.crt'", err)
	}

	if strings.Contains(errStr, "certificate is not valid for any names") ||
		strings.Contains(errStr, "hostname mismatch") {
		return fmt.Errorf("%w\n  👉 Tip: Certificate SAN does not match the requested hostname. Check '--domain' or connection hostname", err)
	}

	return err
}

// ProbeDirectMTLS performs a direct mTLS WebSocket probe to verify an inverted node listener.
func ProbeDirectMTLS(targetAddr, customCAPath string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	target := targetAddr
	if !strings.Contains(target, "://") {
		target = "wss://" + target
	}

	u, err := NormalizeURL(target)
	if err != nil {
		return fmt.Errorf("invalid probe url: %w", err)
	}

	dialer, err := NewWSSDialer(customCAPath)
	if err != nil {
		return fmt.Errorf("failed to build mTLS dialer: %w", err)
	}
	dialer.HandshakeTimeout = timeout

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return FormatTLSError(fmt.Errorf("direct mTLS probe (%s) failed: %w", u.String(), err))
	}
	defer conn.Close()

	return nil
}

