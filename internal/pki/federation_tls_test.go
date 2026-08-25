package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractGatewayID(t *testing.T) {
	tests := []struct {
		name      string
		cert      *x509.Certificate
		wantID    string
		wantError bool
	}{
		{
			name: "From Common Name with .fabric suffix",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "gw-us-east.fabric",
				},
			},
			wantID:    "gw-us-east",
			wantError: false,
		},
		{
			name: "From Common Name with .mesh suffix",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "gw-eu-west.mesh",
				},
			},
			wantID:    "gw-eu-west",
			wantError: false,
		},
		{
			name: "From Common Name plain",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "gw-onprem",
				},
			},
			wantID:    "gw-onprem",
			wantError: false,
		},
		{
			name: "From SAN DNS Names",
			cert: &x509.Certificate{
				Subject:  pkix.Name{},
				DNSNames: []string{"gw-asia-south.fabric", "localhost"},
			},
			wantID:    "gw-asia-south",
			wantError: false,
		},
		{
			name:      "Empty cert",
			cert:      &x509.Certificate{},
			wantID:    "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, err := ExtractGatewayID(tt.cert)
			if (err != nil) != tt.wantError {
				t.Fatalf("ExtractGatewayID() error = %v, wantError %v", err, tt.wantError)
			}
			if gotID != tt.wantID {
				t.Errorf("ExtractGatewayID() = %q, want %q", gotID, tt.wantID)
			}
		})
	}
}

func TestFederationTLSConfigs(t *testing.T) {
	tempDir := t.TempDir()
	ca, err := LoadOrInitCA(tempDir, "fabric.mesh")
	if err != nil {
		t.Fatalf("LoadOrInitCA failed: %v", err)
	}

	caCertPath := filepath.Join(tempDir, "ca.crt")
	if _, err := os.Stat(caCertPath); err != nil {
		t.Fatalf("ca.crt not found: %v", err)
	}

	leafCert, err := ca.MintCertificate([]string{"gw-test.fabric"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("MintCertificate failed: %v", err)
	}

	serverTLS, err := BuildFederationServerTLSConfig(caCertPath, *leafCert)
	if err != nil {
		t.Fatalf("BuildFederationServerTLSConfig failed: %v", err)
	}
	if serverTLS.ClientCAs == nil {
		t.Errorf("expected ClientCAs to be populated")
	}

	clientTLS, err := BuildFederationClientTLSConfig(caCertPath, leafCert)
	if err != nil {
		t.Fatalf("BuildFederationClientTLSConfig failed: %v", err)
	}
	if clientTLS.RootCAs == nil {
		t.Errorf("expected RootCAs to be populated")
	}
}
