package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Standard capability constants.
const (
	CapabilityInspect = "inspect"
	CapabilityExec    = "exec"
	CapabilityCopy    = "copy"
	CapabilityProxy   = "proxy"
	CapabilityAdmin   = "admin"
	CapabilityPeer    = "peer"
	CapabilityThread  = "thread"
)

// SessionIdentity represents an authenticated principal and its granted capabilities.
type SessionIdentity struct {
	Token        string          `json:"token,omitempty"`
	Role         string          `json:"role"`
	Capabilities map[string]bool `json:"capabilities"`
	RemoteIP     string          `json:"remote_ip"`
	CreatedAt    time.Time       `json:"created_at"`
}

// HasCapability checks whether this session identity has the requested capability.
// Admin role or "admin" capability grants universal access to all capabilities.
func (s *SessionIdentity) HasCapability(capName string) bool {
	if s == nil {
		return false
	}
	if s.Role == "admin" || (s.Capabilities != nil && s.Capabilities[CapabilityAdmin]) {
		return true
	}
	if s.Capabilities == nil {
		return false
	}
	return s.Capabilities[capName]
}

// IPRateLimiter provides sliding-window rate limiting for IP addresses.
type IPRateLimiter struct {
	mu          sync.Mutex
	failures    map[string][]time.Time
	maxAttempts int
	window      time.Duration
	stopCh      chan struct{}
}

// NewIPRateLimiter creates a new sliding-window rate limiter.
func NewIPRateLimiter(maxAttempts int, window time.Duration) *IPRateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	limiter := &IPRateLimiter{
		failures:    make(map[string][]time.Time),
		maxAttempts: maxAttempts,
		window:      window,
		stopCh:      make(chan struct{}),
	}
	go limiter.cleanupLoop()
	return limiter
}

func filterValid(times []time.Time, cutoff time.Time) []time.Time {
	var valid []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	return valid
}

func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case now := <-ticker.C:
			l.mu.Lock()
			cutoff := now.Add(-l.window)
			for ip, times := range l.failures {
				valid := filterValid(times, cutoff)
				if len(valid) == 0 {
					delete(l.failures, ip)
				} else {
					l.failures[ip] = valid
				}
			}
			l.mu.Unlock()
		}
	}
}

// RecordFailure records a failed authentication attempt for an IP.
func (l *IPRateLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	valid := append(filterValid(l.failures[ip], cutoff), now)
	l.failures[ip] = valid
}

// IsRateLimited checks if the given IP has exceeded the max failed attempts in the window.
func (l *IPRateLimiter) IsRateLimited(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	valid := filterValid(l.failures[ip], cutoff)
	return len(valid) >= l.maxAttempts
}

// Reset clears failure history for an IP (e.g. after successful auth or in tests).
func (l *IPRateLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}

// Close stops the background cleanup loop.
func (l *IPRateLimiter) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
}

// AccessControllerConfig configures the AccessController.
type AccessControllerConfig struct {
	ClusterToken      string
	AdminToken        string
	MaxFailedAttempts int
	RateLimitWindow   time.Duration
}

// AccessController validates credentials, manages capability-scoped tokens,
// and enforces sliding-window rate limiting.
type AccessController struct {
	mu           sync.RWMutex
	clusterToken string
	adminToken   string
	scopedTokens map[string]*SessionIdentity
	rateLimiter  *IPRateLimiter
}

// NewAccessController instantiates an AccessController.
func NewAccessController(cfg AccessControllerConfig) *AccessController {
	return &AccessController{
		clusterToken: cfg.ClusterToken,
		adminToken:   cfg.AdminToken,
		scopedTokens: make(map[string]*SessionIdentity),
		rateLimiter:  NewIPRateLimiter(cfg.MaxFailedAttempts, cfg.RateLimitWindow),
	}
}

// RateLimiter returns the attached IPRateLimiter.
func (ac *AccessController) RateLimiter() *IPRateLimiter {
	return ac.rateLimiter
}

// RegisterScopedToken registers a custom token with a specific role and capability set.
func (ac *AccessController) RegisterScopedToken(token, role string, caps []string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	capMap := make(map[string]bool)
	for _, c := range caps {
		capMap[c] = true
	}

	ac.scopedTokens[token] = &SessionIdentity{
		Token:        token,
		Role:         role,
		Capabilities: capMap,
	}
}

// ExtractIP extracts the client IP address from a remote address string.
func ExtractIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// ExtractToken extracts a token from the Request headers, query params, or subprotocols.
func (ac *AccessController) ExtractToken(r *http.Request) string {
	// 1. Authorization: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if authHeader != "" && !strings.Contains(authHeader, " ") {
		return strings.TrimSpace(authHeader)
	}

	// 2. X-Fabric-Token header
	if tok := r.Header.Get("X-Fabric-Token"); tok != "" {
		return strings.TrimSpace(tok)
	}

	// 3. Query params: ?token=... or ?auth=...
	if tok := r.URL.Query().Get("token"); tok != "" {
		return strings.TrimSpace(tok)
	}
	if tok := r.URL.Query().Get("auth"); tok != "" {
		return strings.TrimSpace(tok)
	}

	// 4. Sec-WebSocket-Protocol: token.<token> or <token>
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		parts := strings.Split(proto, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if strings.HasPrefix(trimmed, "token.") {
				return strings.TrimPrefix(trimmed, "token.")
			}
		}
	}

	return ""
}

func constantTimeMatch(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// AuthenticateRequest authenticates an HTTP request, validates capabilities,
// and enforces sliding-window IP rate limiting.
func (ac *AccessController) AuthenticateRequest(r *http.Request, requiredCaps ...string) (*SessionIdentity, int, error) {
	ip := ExtractIP(r.RemoteAddr)

	// 1. Check rate limit
	if ac.rateLimiter.IsRateLimited(ip) {
		return nil, http.StatusTooManyRequests, errors.New("rate limit exceeded: too many unauthorized attempts")
	}

	token := ac.ExtractToken(r)

	ac.mu.RLock()
	clusterTok := ac.clusterToken
	adminTok := ac.adminToken
	scopedMap := make(map[string]*SessionIdentity, len(ac.scopedTokens))
	for k, v := range ac.scopedTokens {
		scopedMap[k] = v
	}
	ac.mu.RUnlock()

	var ident *SessionIdentity

	// 2. If no tokens are configured at all, grant open default access
	if clusterTok == "" && adminTok == "" && len(scopedMap) == 0 {
		ident = newAdminIdentity("", ip)
	} else if adminTok != "" && constantTimeMatch(token, adminTok) {
		ident = newAdminIdentity(token, ip)
	} else if clusterTok != "" && constantTimeMatch(token, clusterTok) {
		isAdmin := (adminTok == "")
		ident = &SessionIdentity{
			Token: token,
			Role:  "cluster",
			Capabilities: map[string]bool{
				CapabilityAdmin:   isAdmin,
				CapabilityPeer:    true,
				CapabilityInspect: true,
				CapabilityExec:    true,
				CapabilityCopy:    true,
				CapabilityProxy:   true,
				CapabilityThread:  true,
			},
			RemoteIP:  ip,
			CreatedAt: time.Now(),
		}
	} else if scoped, ok := scopedMap[token]; ok && token != "" {
		capCopy := make(map[string]bool, len(scoped.Capabilities))
		for k, v := range scoped.Capabilities {
			capCopy[k] = v
		}
		ident = &SessionIdentity{
			Token:        token,
			Role:         scoped.Role,
			Capabilities: capCopy,
			RemoteIP:     ip,
			CreatedAt:    time.Now(),
		}
	}

	// 3. Failed authentication
	if ident == nil {
		ac.rateLimiter.RecordFailure(ip)
		return nil, http.StatusUnauthorized, errors.New("unauthorized: invalid or missing token")
	}

	// 4. Validate required capabilities
	for _, capName := range requiredCaps {
		if !ident.HasCapability(capName) {
			return nil, http.StatusForbidden, fmt.Errorf("forbidden: missing capability %q", capName)
		}
	}

	return ident, http.StatusOK, nil
}

// Close cleans up rate limiter resources.
func (ac *AccessController) Close() {
	if ac.rateLimiter != nil {
		ac.rateLimiter.Close()
	}
}

func newAdminIdentity(token, ip string) *SessionIdentity {
	return &SessionIdentity{
		Token: token,
		Role:  "admin",
		Capabilities: map[string]bool{
			CapabilityAdmin:   true,
			CapabilityInspect: true,
			CapabilityExec:    true,
			CapabilityCopy:    true,
			CapabilityProxy:   true,
			CapabilityPeer:    true,
			CapabilityThread:  true,
		},
		RemoteIP:  ip,
		CreatedAt: time.Now(),
	}
}

