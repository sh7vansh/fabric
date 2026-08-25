package pki

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
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

func TestFederationMTLSHandshake(t *testing.T) {
	tempDir := t.TempDir()
	ca, err := LoadOrInitCA(tempDir, "fabric.mesh")
	if err != nil {
		t.Fatalf("LoadOrInitCA failed: %v", err)
	}
	caCertPath := filepath.Join(tempDir, "ca.crt")

	serverLeaf, err := ca.MintCertificate([]string{"gw-server.fabric"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("MintCertificate failed: %v", err)
	}

	validClientLeaf, err := ca.MintCertificate([]string{"gw-client.fabric"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("MintCertificate failed: %v", err)
	}

	// Another independent CA (untrusted)
	otherDir := t.TempDir()
	otherCA, err := LoadOrInitCA(otherDir, "fabric.mesh")
	if err != nil {
		t.Fatalf("LoadOrInitCA for other CA failed: %v", err)
	}
	untrustedClientLeaf, err := otherCA.MintCertificate([]string{"gw-untrusted.fabric"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("MintCertificate for untrusted client failed: %v", err)
	}

	serverTLS, err := BuildFederationServerTLSConfig(caCertPath, *serverLeaf)
	if err != nil {
		t.Fatalf("BuildFederationServerTLSConfig failed: %v", err)
	}

	// Create listener
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn, ok := c.(*tls.Conn)
				if ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	// 1. Valid client with mTLS cert -> Should succeed
	validClientTLS, err := BuildFederationClientTLSConfig(caCertPath, validClientLeaf)
	if err != nil {
		t.Fatalf("BuildFederationClientTLSConfig failed: %v", err)
	}
	validClientTLS.ServerName = "gw-server.fabric"
	validConn, err := tls.Dial("tcp", ln.Addr().String(), validClientTLS)
	if err != nil {
		t.Errorf("expected valid mTLS dial to succeed, got: %v", err)
	} else {
		state := validConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			t.Errorf("expected peer certificates from server")
		}
		validConn.Close()
	}

	// 2. Untrusted client cert -> Should fail handshake
	untrustedClientTLS, err := BuildFederationClientTLSConfig(caCertPath, untrustedClientLeaf)
	if err != nil {
		t.Fatalf("BuildFederationClientTLSConfig failed: %v", err)
	}
	untrustedClientTLS.ServerName = "gw-server.fabric"
	untrustedConn, err := tls.Dial("tcp", ln.Addr().String(), untrustedClientTLS)
	if err == nil {
		buf := make([]byte, 4)
		_, readErr := untrustedConn.Read(buf)
		untrustedConn.Close()
		if readErr == nil {
			t.Errorf("expected untrusted client mTLS handshake to fail on server verification")
		}
	}

	// 3. No client cert presented -> Should fail handshake
	noCertClientTLS, err := BuildFederationClientTLSConfig(caCertPath, nil)
	if err != nil {
		t.Fatalf("BuildFederationClientTLSConfig failed: %v", err)
	}
	noCertClientTLS.ServerName = "gw-server.fabric"
	noCertConn, err := tls.Dial("tcp", ln.Addr().String(), noCertClientTLS)
	if err == nil {
		buf := make([]byte, 4)
		_, readErr := noCertConn.Read(buf)
		noCertConn.Close()
		if readErr == nil {
			t.Errorf("expected no-cert client mTLS handshake to fail on server verification")
		}
	}
}

