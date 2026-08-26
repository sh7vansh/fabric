package pki

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxCachedLeafCerts is the default capacity for the in-memory leaf certificate cache.
const MaxCachedLeafCerts = 512

// CA manages an in-process Certificate Authority and mints leaf certificates.
type CA struct {
	mu           sync.RWMutex
	dir          string
	domain       string
	rootCert     *x509.Certificate
	rootKey      crypto.Signer
	certPEM      []byte
	keyPEM       []byte
	certPool     *x509.CertPool
	leafCache    map[string]*list.Element
	lruList      *list.List
	maxCache     int
	activeNodes  func() []string
	allowedHosts []string
}

type cachedCert struct {
	key       string
	cert      *tls.Certificate
	expiresAt time.Time
}

// Option configures CA behavior.
type Option func(*caOptions)

type caOptions struct {
	rootValidity time.Duration
	leafValidity time.Duration
	maxCache     int
	activeNodes  func() []string
	allowedHosts []string
}

func defaultOptions() *caOptions {
	return &caOptions{
		rootValidity: 10 * 365 * 24 * time.Hour, // 10 years
		leafValidity: 90 * 24 * time.Hour,       // 90 days
		maxCache:     MaxCachedLeafCerts,
	}
}

// WithRootValidity overrides the CA root certificate lifetime.
func WithRootValidity(d time.Duration) Option {
	return func(o *caOptions) {
		o.rootValidity = d
	}
}

// WithLeafValidity overrides the default minted leaf certificate lifetime.
func WithLeafValidity(d time.Duration) Option {
	return func(o *caOptions) {
		o.leafValidity = d
	}
}

// WithMaxCache overrides the maximum number of cached leaf certificates.
func WithMaxCache(maxEntries int) Option {
	return func(o *caOptions) {
		o.maxCache = maxEntries
	}
}

// WithActiveNodes provides a dynamic node validator callback for SNI checks.
func WithActiveNodes(fn func() []string) Option {
	return func(o *caOptions) {
		o.activeNodes = fn
	}
}

// WithAllowedHosts configures statically authorized SNI hostnames.
func WithAllowedHosts(hosts []string) Option {
	return func(o *caOptions) {
		o.allowedHosts = hosts
	}
}

// LoadOrInitCA loads an existing CA from storage directory or creates a new one.
func LoadOrInitCA(dir, domain string, opts ...Option) (*CA, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca := &CA{
		dir:          dir,
		domain:       domain,
		leafCache:    make(map[string]*list.Element),
		lruList:      list.New(),
		maxCache:     options.maxCache,
		activeNodes:  options.activeNodes,
		allowedHosts: options.allowedHosts,
	}

	if fileExists(certPath) && fileExists(keyPath) {
		if err := ca.loadFromDisk(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("failed to load existing CA: %w", err)
		}
	} else {
		if err := ca.generateRoot(options.rootValidity); err != nil {
			return nil, fmt.Errorf("failed to generate new root CA: %w", err)
		}
		if err := ca.saveToDisk(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("failed to save new root CA: %w", err)
		}
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	ca.certPool = pool

	// Automatically ensure client certificate & key exist in CA dir and ~/.fabric
	_ = ca.EnsureClientCertificate(dir)
	if home, err := os.UserHomeDir(); err == nil {
		fabricDir := filepath.Join(home, ".fabric")
		if fabricDir != dir {
			_ = ca.EnsureClientCertificate(fabricDir)
		}
	}

	// Pre-mint server and gateway certificates for configured cluster domain
	preMint := [][]string{
		{"localhost", "127.0.0.1", "::1"},
	}
	if domain != "" {
		preMint = append(preMint,
			[]string{domain},
			[]string{"gateway." + domain, domain},
			[]string{"server." + domain, domain},
			[]string{"socket." + domain, domain},
		)
	}
	for _, h := range preMint {
		_, _ = ca.MintCertificate(h, options.leafValidity)
	}

	return ca, nil
}

// EnsureClientCertificate checks if client.crt and client.key exist in destDir.
// If either is missing, it mints a client certificate and writes both files.
func (c *CA) EnsureClientCertificate(destDir string) error {
	if destDir == "" {
		return nil
	}
	certPath := filepath.Join(destDir, "client.crt")
	keyPath := filepath.Join(destDir, "client.key")
	caCertPath := filepath.Join(destDir, "ca.crt")

	// Ensure ca.crt also exists in destDir if not already present
	if !fileExists(caCertPath) && len(c.certPEM) > 0 {
		_ = os.MkdirAll(destDir, 0755)
		_ = os.WriteFile(caCertPath, c.certPEM, 0644)
	}

	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}

	hosts := []string{"fabric-client", "localhost", "127.0.0.1", "::1"}
	if c.domain != "" {
		hosts = append(hosts, "*."+c.domain, c.domain)
	}

	certPEM, keyPEM, err := c.MintCertificatePEM(hosts, 365*24*time.Hour)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (c *CA) generateRoot(validity time.Duration) error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate root ecdsa key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("generate root serial: %w", err)
	}

	cn := "Fabric Mesh Root CA"
	if c.domain != "" {
		cn = fmt.Sprintf("Fabric Mesh Root CA (%s)", c.domain)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Fabric Mesh Authority"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("create root cert: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("parse root cert: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal root private key: %w", err)
	}

	c.rootCert = parsedCert
	c.rootKey = privKey
	c.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	c.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return nil
}

func (c *CA) loadFromDisk(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("failed to decode root cert PEM")
	}

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse root cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode root key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse root key: %w", err)
	}

	c.rootCert = parsedCert
	c.rootKey = key
	c.certPEM = certPEM
	c.keyPEM = keyPEM
	return nil
}

func (c *CA) saveToDisk(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, c.certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, c.keyPEM, 0600)
}

// CertPEM returns the raw PEM-encoded Root CA certificate.
func (c *CA) CertPEM() []byte {
	return c.certPEM
}

// CertPool returns an x509.CertPool containing this Root CA.
func (c *CA) CertPool() *x509.CertPool {
	return c.certPool
}

// RootCert returns the parsed x509 Root CA certificate.
func (c *CA) RootCert() *x509.Certificate {
	return c.rootCert
}

// MintCertificate creates or retrieves a cached TLS leaf certificate for the given hostnames/IPs.
func (c *CA) MintCertificate(hosts []string, validity time.Duration) (*tls.Certificate, error) {
	if len(hosts) == 0 {
		return nil, errors.New("cannot mint certificate without hostnames")
	}

	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}

	cacheKey := normalizeHostsKey(hosts)

	c.mu.Lock()
	if elem, ok := c.leafCache[cacheKey]; ok {
		cached := elem.Value.(*cachedCert)
		if time.Now().Add(5 * time.Minute).Before(cached.expiresAt) {
			c.lruList.MoveToFront(elem)
			c.mu.Unlock()
			return cached.cert, nil
		}
		c.lruList.Remove(elem)
		delete(c.leafCache, cacheKey)
	}
	c.mu.Unlock()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf ecdsa key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Minute)
	notAfter := time.Now().Add(validity)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hosts[0],
			Organization: []string{"Fabric Mesh Node"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, strings.ToLower(h))
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, c.rootCert, &privKey.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf private key: %w", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Bundle leaf cert with root CA cert
	fullChainPEM := append(leafCertPEM, c.certPEM...)

	tlsCert, err := tls.X509KeyPair(fullChainPEM, leafKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls.X509KeyPair: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check cache under lock
	if elem, ok := c.leafCache[cacheKey]; ok {
		cached := elem.Value.(*cachedCert)
		if time.Now().Add(5 * time.Minute).Before(cached.expiresAt) {
			c.lruList.MoveToFront(elem)
			return cached.cert, nil
		}
		c.lruList.Remove(elem)
		delete(c.leafCache, cacheKey)
	}

	// LRU eviction if at or above capacity
	maxCap := c.maxCache
	if maxCap <= 0 {
		maxCap = MaxCachedLeafCerts
	}
	for c.lruList.Len() >= maxCap && c.lruList.Len() > 0 {
		oldest := c.lruList.Back()
		if oldest != nil {
			c.lruList.Remove(oldest)
			delete(c.leafCache, oldest.Value.(*cachedCert).key)
		}
	}

	entry := &cachedCert{
		key:       cacheKey,
		cert:      &tlsCert,
		expiresAt: notAfter,
	}
	elem := c.lruList.PushFront(entry)
	c.leafCache[cacheKey] = elem

	return &tlsCert, nil
}

// MintCertificatePEM creates or retrieves a TLS leaf certificate and returns PEM-encoded cert and private key bytes.
func (c *CA) MintCertificatePEM(hosts []string, validity time.Duration) ([]byte, []byte, error) {
	tlsCert, err := c.MintCertificate(hosts, validity)
	if err != nil {
		return nil, nil, err
	}

	var certBuf bytes.Buffer
	for _, certBytes := range tlsCert.Certificate {
		if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
			return nil, nil, fmt.Errorf("pem encode cert: %w", err)
		}
	}

	ecKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not an ECDSA private key")
	}

	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ec private key: %w", err)
	}

	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, nil, fmt.Errorf("pem encode private key: %w", err)
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}

func (c *CA) isAllowedSNI(serverName string) bool {
	if serverName == "" || serverName == "localhost" || net.ParseIP(serverName) != nil {
		return true
	}
	serverName = strings.ToLower(serverName)
	if c.domain != "" {
		if serverName == c.domain || serverName == "gateway."+c.domain || serverName == "server."+c.domain || serverName == "socket."+c.domain {
			return true
		}
	}
	if c.allowedHosts != nil {
		for _, h := range c.allowedHosts {
			if strings.EqualFold(h, serverName) {
				return true
			}
		}
	}
	if c.activeNodes != nil {
		for _, n := range c.activeNodes() {
			if strings.EqualFold(n, serverName) || (c.domain != "" && strings.EqualFold(n+"."+c.domain, serverName)) {
				return true
			}
		}
	}
	return false
}

// GetCertificate returns a tls.Config.GetCertificate SNI handler.
func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if h, _, err := net.SplitHostPort(serverName); err == nil {
		serverName = h
	}

	if !c.isAllowedSNI(serverName) {
		return nil, fmt.Errorf("sni %q not authorized for internal CA minting", hello.ServerName)
	}

	hosts := []string{}
	if serverName == "" || serverName == "localhost" {
		hosts = append(hosts, "localhost", "127.0.0.1", "::1")
	} else {
		hosts = append(hosts, serverName)
		if !strings.Contains(serverName, ".") && c.domain != "" {
			hosts = append(hosts, serverName+"."+c.domain)
		}
	}

	return c.MintCertificate(hosts, 90*24*time.Hour)
}

// TLSConfig returns a preconfigured server tls.Config backed by this CA.
func (c *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: c.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func normalizeHostsKey(hosts []string) string {
	sorted := make([]string, len(hosts))
	copy(sorted, hosts)
	for i, s := range sorted {
		sorted[i] = strings.ToLower(s)
	}
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}
