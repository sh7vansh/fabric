package meshdns

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fabric/internal/protocol"

	"github.com/google/uuid"
	"github.com/miekg/dns"
)

const (
	defaultHostsPath  = "/etc/hosts"
	hostsBlockStart   = "# BEGIN FABRIC MESH"
	hostsBlockEnd     = "# END FABRIC MESH"
	defaultListenAddr = "127.0.0.1:53535"
)

type dnsCacheEntry struct {
	resp      protocol.DNSResponse
	expiresAt time.Time
}

var hostsFileLock sync.Mutex

// SystemDNSManager is a deep module encapsulating local stub DNS resolution,
// systemd-resolved split-DNS configuration, and fallback /etc/hosts manipulation.
type SystemDNSManager struct {
	domain      string
	listenAddr  string
	hostsPath   string
	skipOSOps   bool // For testing without touching OS files or running systemctl
	useResolved bool

	mux           *protocol.StreamMultiplexer
	cache         map[string]dnsCacheEntry
	cacheMux      sync.RWMutex
	stopCacheLoop chan struct{}
	cacheLoopOnce sync.Once
	pending       map[string]chan protocol.DNSResponse
	pendMux       sync.Mutex
	server        *dns.Server
	serverMux     sync.Mutex
}

// NewSystemDNSManager creates a new SystemDNSManager for the specified mesh domain.
func NewSystemDNSManager(domain string) *SystemDNSManager {
	mgr := &SystemDNSManager{
		domain:        domain,
		listenAddr:    defaultListenAddr,
		hostsPath:     defaultHostsPath,
		useResolved:   HasSystemdResolved(),
		cache:         make(map[string]dnsCacheEntry),
		stopCacheLoop: make(chan struct{}),
		pending:       make(map[string]chan protocol.DNSResponse),
	}
	go mgr.evictionLoop()
	return mgr
}

func (m *SystemDNSManager) evictionLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCacheLoop:
			return
		case now := <-ticker.C:
			m.cacheMux.Lock()
			for k, entry := range m.cache {
				if now.After(entry.expiresAt) {
					delete(m.cache, k)
				}
			}
			m.cacheMux.Unlock()
		}
	}
}

// SetMultiplexer attaches an active StreamMultiplexer for routing unresolved mesh DNS queries.
func (m *SystemDNSManager) SetMultiplexer(mux *protocol.StreamMultiplexer) {
	m.cacheMux.Lock()
	defer m.cacheMux.Unlock()
	m.mux = mux
}

// Start initializes the local UDP DNS listener and configures the OS resolver routing.
func (m *SystemDNSManager) Start() error {
	// 1. Initial cleanup of previous stale state
	m.Teardown()

	// 2. Start local UDP stub DNS server
	m.serverMux.Lock()
	m.server = &dns.Server{Addr: m.listenAddr, Net: "udp", Handler: m}
	m.serverMux.Unlock()

	go func() {
		if err := m.server.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "closed") {
			log.Printf("[DNS] Stub resolver listener info: %v\n", err)
		}
	}()

	// 3. Configure OS-level routing
	if !m.skipOSOps {
		if m.useResolved {
			if err := m.configureSystemdResolved(); err != nil {
				log.Printf("[DNS] Warning: failed to configure systemd-resolved: %v (falling back to /etc/hosts)\n", err)
				m.useResolved = false
			}
		}
	}

	return nil
}

// SyncNodes updates the host name resolution table when the Socket broadcasts connected nodes.
func (m *SystemDNSManager) SyncNodes(nodes []protocol.NodeMetadata, socketURL string) {
	if m.useResolved {
		// systemd-resolved dynamically queries the local stub resolver; no static hosts update needed
		return
	}

	// Fallback to /etc/hosts block
	u, err := url.Parse(socketURL)
	if err != nil {
		return
	}
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return
	}
	socketIP := ips[0].String()

	m.updateHostsBlock(nodes, socketIP)
}

// Teardown cleanly reverts OS DNS configuration, cleans /etc/hosts blocks, and shuts down the DNS server.
func (m *SystemDNSManager) Teardown() {
	m.cacheLoopOnce.Do(func() {
		if m.stopCacheLoop != nil {
			close(m.stopCacheLoop)
		}
	})

	if !m.skipOSOps {
		if m.useResolved {
			m.revertSystemdResolved()
		}
		m.cleanHostsBlock()
	}

	m.serverMux.Lock()
	if m.server != nil {
		m.server.Shutdown()
		m.server = nil
	}
	m.serverMux.Unlock()
}

// HandleDNSResponse routes a response from the Socket back to waiting DNS query sessions.
func (m *SystemDNSManager) HandleDNSResponse(resp protocol.DNSResponse) {
	if resp.RCode == dns.RcodeSuccess && resp.TTL > 0 {
		replyWire, err := base64.StdEncoding.DecodeString(resp.Data)
		if err == nil {
			reply := new(dns.Msg)
			if err := reply.Unpack(replyWire); err == nil && len(reply.Question) > 0 {
				name := strings.ToLower(reply.Question[0].Name)
				m.cacheMux.Lock()
				m.cache[name] = dnsCacheEntry{
					resp:      resp,
					expiresAt: time.Now().Add(time.Duration(resp.TTL) * time.Second),
				}
				m.cacheMux.Unlock()
			}
		}
	}

	m.pendMux.Lock()
	ch, ok := m.pending[resp.SessionID]
	if ok {
		delete(m.pending, resp.SessionID)
	}
	m.pendMux.Unlock()

	if ok {
		ch <- resp
	}
}

// ServeDNS handles incoming RFC 1035 UDP DNS queries on localhost:53535.
func (m *SystemDNSManager) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	name := strings.ToLower(q.Name)

	suffixMatched := false
	for _, s := range []string{"." + m.domain + ".", ".fabric.", ".mesh."} {
		if strings.HasSuffix(name, s) {
			suffixMatched = true
			break
		}
	}
	if !suffixMatched {
		dns.HandleFailed(w, req)
		return
	}

	m.cacheMux.RLock()
	cachedEntry, found := m.cache[name]
	mux := m.mux
	m.cacheMux.RUnlock()

	if found && time.Now().Before(cachedEntry.expiresAt) {
		replyWire, err := base64.StdEncoding.DecodeString(cachedEntry.resp.Data)
		if err == nil {
			reply := new(dns.Msg)
			if err := reply.Unpack(replyWire); err == nil {
				reply.Id = req.Id
				w.WriteMsg(reply)
				return
			}
		}
	}

	if mux == nil {
		dns.HandleFailed(w, req)
		return
	}

	reqWire, err := req.Pack()
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	sessionID := uuid.New().String()
	ch := make(chan protocol.DNSResponse, 1)

	m.pendMux.Lock()
	m.pending[sessionID] = ch
	m.pendMux.Unlock()

	query := protocol.DNSQuery{
		Type:      protocol.TypeDNSQuery,
		SessionID: sessionID,
		Name:      name,
		QType:     q.Qtype,
		Data:      base64.StdEncoding.EncodeToString(reqWire),
	}

	go func() {
		stream, err := mux.Session.Open()
		if err == nil {
			b, _ := json.Marshal(query)
			stream.Write(b)
			stream.Close()
		}
	}()

	select {
	case resp := <-ch:
		replyWire, err := base64.StdEncoding.DecodeString(resp.Data)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}

		reply := new(dns.Msg)
		if err := reply.Unpack(replyWire); err != nil {
			dns.HandleFailed(w, req)
			return
		}

		reply.Id = req.Id
		w.WriteMsg(reply)
	case <-time.After(5 * time.Second):
		m.pendMux.Lock()
		delete(m.pending, sessionID)
		m.pendMux.Unlock()
		dns.HandleFailed(w, req)
	}
}

// HasSystemdResolved checks if systemd-resolved is active on Linux.
func HasSystemdResolved() bool {
	_, err := os.Stat("/run/systemd/resolve/stub-resolv.conf")
	return err == nil
}

func (m *SystemDNSManager) configureSystemdResolved() error {
	exec.Command("resolvectl", "revert", "lo").Run()

	cmd := exec.Command("resolvectl", "domain", "lo", "~"+m.domain)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("resolvectl domain failed: %w", err)
	}

	cmd = exec.Command("resolvectl", "dns", "lo", m.listenAddr)
	if err := cmd.Run(); err != nil {
		log.Printf("[DNS] Warning: resolvectl dns failed: %v\n", err)
	}

	cmd = exec.Command("resolvectl", "default-route", "lo", "false")
	if err := cmd.Run(); err != nil {
		log.Printf("[DNS] Warning: resolvectl default-route failed: %v\n", err)
	}

	return nil
}

func (m *SystemDNSManager) revertSystemdResolved() {
	exec.Command("resolvectl", "revert", "lo").Run()
}

func (m *SystemDNSManager) readAndStripHostsBlock() ([]string, error) {
	content, err := os.ReadFile(m.hostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == hostsBlockStart {
			inBlock = true
			continue
		}
		if trimmed == hostsBlockEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			newLines = append(newLines, line)
		}
	}

	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}
	return newLines, nil
}

func (m *SystemDNSManager) commitHostsLines(lines []string) error {
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	return m.writeHostsFileAtomic(strings.Join(lines, "\n"))
}

func (m *SystemDNSManager) updateHostsBlock(nodes []protocol.NodeMetadata, socketIP string) {
	hostsFileLock.Lock()
	defer hostsFileLock.Unlock()

	newLines, err := m.readAndStripHostsBlock()
	if err != nil {
		return
	}

	newLines = append(newLines, hostsBlockStart)
	for _, n := range nodes {
		// Strict RFC 1123 DNS hostname validation to prevent /etc/hosts injection
		if protocol.IsValidHostname(n.Hostname) {
			newLines = append(newLines, socketIP+" "+n.Hostname+"."+m.domain)
		}
	}
	newLines = append(newLines, hostsBlockEnd)

	_ = m.commitHostsLines(newLines)
}

func (m *SystemDNSManager) cleanHostsBlock() {
	hostsFileLock.Lock()
	defer hostsFileLock.Unlock()

	newLines, err := m.readAndStripHostsBlock()
	if err != nil {
		return
	}

	_ = m.commitHostsLines(newLines)
}

func (m *SystemDNSManager) writeHostsFileAtomic(content string) error {
	dir := filepath.Dir(m.hostsPath)
	tmpFile, err := os.CreateTemp(dir, ".hosts.fabric.tmp-*")
	if err != nil {
		tmpFile, err = os.CreateTemp("", ".hosts.fabric.tmp-*")
		if err != nil {
			return err
		}
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, m.hostsPath); err != nil {
		// Fallback copy if rename fails across filesystems / mount points
		data, rErr := os.ReadFile(tmpPath)
		if rErr != nil {
			return err
		}
		if wErr := os.WriteFile(m.hostsPath, data, 0644); wErr != nil {
			return wErr
		}
	}

	return nil
}
