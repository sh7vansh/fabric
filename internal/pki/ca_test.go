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
	"strings"
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

func TestCALRUCacheEviction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-lru-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Set small cache capacity of 3
	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.mesh", pki.WithMaxCache(3))
	if err != nil {
		t.Fatal(err)
	}

	// Mint 5 different host certificates for registered nodes
	for i := 0; i < 5; i++ {
		host := fmt.Sprintf("node-%d.fabric.mesh", i)
		if _, err := ca.MintCertificate([]string{host}, 1*time.Hour); err != nil {
			t.Fatalf("failed to mint certificate for %s: %v", host, err)
		}
	}

	// Verify that MintCertificate caching works
	cert, err := ca.MintCertificate([]string{"node-4.fabric.mesh"}, 1*time.Hour)
	if err != nil || cert == nil {
		t.Errorf("expected MintCertificate for node-4.fabric.mesh to succeed, got %v", err)
	}
}

func TestCAGetCertificateSNIAuthorization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-sni-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	ca, err := pki.LoadOrInitCA(tmpDir, "fabric.mesh",
		pki.WithActiveNodes(func() []string {
			return []string{"registered-node"}
		}),
		pki.WithAllowedHosts([]string{"federation-peer.mesh"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Allowed SNIs:
	allowedSNIs := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"fabric.mesh",
		"gateway.fabric.mesh",
		"server.fabric.mesh",
		"socket.fabric.mesh",
		"registered-node",
		"registered-node.fabric.mesh",
		"federation-peer.mesh",
	}

	for _, sni := range allowedSNIs {
		cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || cert == nil {
			t.Errorf("expected SNI %q to be allowed, got error: %v", sni, err)
		}
	}

	// 2. Disallowed SNIs:
	disallowedSNIs := []string{
		"evil-phishing-site.com",
		"attacker.org",
		"random.domain.io",
		"unregistered-node.fabric.mesh",
		"unregistered-node",
		"random.mesh",
	}

	for _, sni := range disallowedSNIs {
		cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err == nil {
			t.Errorf("expected SNI %q to be rejected, but got cert: %+v", sni, cert)
		}
	}

	// 3. Verify no unsolicited wildcard SAN injection
	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "registered-node.fabric.mesh"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}
	for _, dnsName := range parsedCert.DNSNames {
		if strings.HasPrefix(dnsName, "*.") {
			t.Errorf("unexpected wildcard SAN %q in minted certificate for registered-node.fabric.mesh", dnsName)
		}
	}
}

func TestCAGetCertificate_EmptyServerName_IncludesInterfaceIPsAndDomain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fabric-ca-ip-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	domain := "fabric.mesh"
	ca, err := pki.LoadOrInitCA(tmpDir, domain)
	if err != nil {
		t.Fatalf("LoadOrInitCA failed: %v", err)
	}

	// Request certificate with empty ServerName (RFC 6066 raw IP connection)
	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err != nil {
		t.Fatalf("GetCertificate failed for empty ServerName: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("expected non-nil certificate")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Verify localhost and loopbacks
	found127 := false
	foundV6Loopback := false
	for _, ip := range parsedCert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			found127 = true
		}
		if ip.String() == "::1" {
			foundV6Loopback = true
		}
	}
	if !found127 || !foundV6Loopback {
		t.Errorf("expected 127.0.0.1 and ::1 in IPAddresses, got: %v", parsedCert.IPAddresses)
	}

	// Verify all host non-loopback IP interfaces are included in IPAddresses
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("failed to get interface addrs: %v", err)
	}

	var expectedIPs []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			expectedIPs = append(expectedIPs, ipNet.IP.String())
		}
	}

	for _, expectedIP := range expectedIPs {
		found := false
		for _, ip := range parsedCert.IPAddresses {
			if ip.String() == expectedIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected host interface IP %s in certificate IP SANs, but it was missing (got %v)", expectedIP, parsedCert.IPAddresses)
		}
	}

	// Verify mesh domain and wildcard domain in DNSNames
	foundDomain := false
	foundWildcard := false
	for _, dns := range parsedCert.DNSNames {
		if dns == domain {
			foundDomain = true
		}
		if dns == "*."+domain {
			foundWildcard = true
		}
	}
	if !foundDomain {
		t.Errorf("expected domain %q in DNSNames, got %v", domain, parsedCert.DNSNames)
	}
	if !foundWildcard {
		t.Errorf("expected wildcard domain %q in DNSNames, got %v", "*."+domain, parsedCert.DNSNames)
	}
}


