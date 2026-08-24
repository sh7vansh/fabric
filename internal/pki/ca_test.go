package pki_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fabric/internal/pki"
)

func TestCAInitializationAndPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	domain := "fabric.mesh"

	// 1. Initial creation
	ca1, err := pki.LoadOrInitCA(tmpDir, domain)
	if err != nil {
		t.Fatalf("LoadOrInitCA failed: %v", err)
	}

	if ca1.RootCert() == nil {
		t.Fatal("expected non-nil RootCert")
	}
	if !ca1.RootCert().IsCA {
		t.Errorf("expected IsCA = true, got %v", ca1.RootCert().IsCA)
	}
	if !ca1.RootCert().BasicConstraintsValid {
		t.Errorf("expected BasicConstraintsValid = true")
	}
	if ca1.RootCert().Subject.CommonName != "Fabric Mesh Root CA (fabric.mesh)" {
		t.Errorf("unexpected CommonName: %s", ca1.RootCert().Subject.CommonName)
	}

	// Verify files written
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("ca.crt missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("ca.key missing: %v", err)
	}

	// 2. Reloading existing CA
	ca2, err := pki.LoadOrInitCA(tmpDir, domain)
	if err != nil {
		t.Fatalf("Reloading CA failed: %v", err)
	}

	if ca1.RootCert().SerialNumber.Cmp(ca2.RootCert().SerialNumber) != 0 {
		t.Errorf("expected reloaded CA to have same serial number, got %v vs %v",
			ca1.RootCert().SerialNumber, ca2.RootCert().SerialNumber)
	}
}

func TestMintCertificateAndVerification(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-mint-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.mesh")
	if err != nil {
		t.Fatal(err)
	}

	hosts := []string{"node-1.fabric.mesh", "api.node-1.fabric.mesh", "127.0.0.1"}
	tlsCert, err := ca.MintCertificate(hosts, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("MintCertificate failed: %v", err)
	}

	if len(tlsCert.Certificate) == 0 {
		t.Fatal("expected certificate chain in tls.Certificate")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("Parse leaf cert failed: %v", err)
	}

	// Verify verification against CA CertPool
	opts := x509.VerifyOptions{
		Roots:         ca.CertPool(),
		DNSName:       "node-1.fabric.mesh",
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}

	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("Leaf cert failed verification against CA pool: %v", err)
	}

	opts.DNSName = "api.node-1.fabric.mesh"
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("Leaf cert failed verification for SAN api.node-1.fabric.mesh: %v", err)
	}

	// Verify caching returns identical cert
	cachedCert, err := ca.MintCertificate(hosts, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCert != cachedCert {
		t.Errorf("expected cached certificate pointer to match")
	}
}

func TestLiveHTTPSHandshake(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-https-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.mesh")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, ca.TLSConfig())
	defer tlsLn.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "fabric tls secure response")
		}),
	}
	go srv.Serve(tlsLn)
	defer srv.Close()

	// Client configured with CA pool
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: ca.CertPool(),
			},
		},
	}

	serverURL := fmt.Sprintf("https://%s", ln.Addr().String())
	resp, err := client.Get(serverURL)
	if err != nil {
		t.Fatalf("HTTPS GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "fabric tls secure response\n" {
		t.Errorf("unexpected response body: %q", string(body))
	}
}
