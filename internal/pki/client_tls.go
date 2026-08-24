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

// BuildClientTLSConfig constructs a tls.Config with system root CAs and discovered local cluster CAs.
func BuildClientTLSConfig(customCAPath string) (*tls.Config, error) {
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

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// NewWSSDialer constructs a websocket.Dialer configured with cluster root CAs and custom CA support.
func NewWSSDialer(customCAPath string) (*websocket.Dialer, error) {
	tlsCfg, err := BuildClientTLSConfig(customCAPath)
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
