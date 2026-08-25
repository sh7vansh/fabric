package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// ExtractGatewayID parses a peer certificate Subject Common Name or SAN to identify the remote gateway.
func ExtractGatewayID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("nil certificate")
	}

	cleanName := func(raw string) string {
		s := strings.TrimSpace(raw)
		if s == "" {
			return ""
		}
		// Strip known suffixes (.fabric, .mesh)
		s = strings.TrimSuffix(s, ".fabric")
		s = strings.TrimSuffix(s, ".mesh")
		return s
	}

	// 1. Check CommonName first
	if id := cleanName(cert.Subject.CommonName); id != "" {
		return id, nil
	}

	// 2. Check SAN DNSNames
	for _, dnsName := range cert.DNSNames {
		if strings.HasSuffix(dnsName, ".fabric") || strings.HasSuffix(dnsName, ".mesh") {
			if id := cleanName(dnsName); id != "" {
				return id, nil
			}
		}
	}

	// Fallback to first non-localhost DNS name if any
	for _, dnsName := range cert.DNSNames {
		if dnsName != "localhost" && dnsName != "127.0.0.1" && dnsName != "::1" {
			if id := cleanName(dnsName); id != "" {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("no valid GatewayID found in certificate CN or SANs")
}

// LoadFederationCertPool loads the shared Federation Root CA certificate into a CertPool.
func LoadFederationCertPool(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}

	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read federation CA file %s: %w", caPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no valid certificates found in federation CA file %s", caPath)
	}

	return pool, nil
}

// BuildFederationServerTLSConfig constructs a server tls.Config requiring mTLS against the federation CA.
func BuildFederationServerTLSConfig(caPath string, serverCert tls.Certificate) (*tls.Config, error) {
	pool, err := LoadFederationCertPool(caPath)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	if pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

// BuildFederationClientTLSConfig constructs a client tls.Config authenticating against the federation CA.
func BuildFederationClientTLSConfig(caPath string, clientCert *tls.Certificate) (*tls.Config, error) {
	pool, err := LoadFederationCertPool(caPath)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if pool != nil {
		cfg.RootCAs = pool
	}

	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}

	return cfg, nil
}
