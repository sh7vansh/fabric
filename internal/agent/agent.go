package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fabric/internal/meshdns"
	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/version"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var (
	validUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*$`)
	validEnvKeyRegex   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

var blockedEnvKeys = map[string]bool{
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"LD_AUDIT":        true,
	"IFS":             true,
	"BASH_ENV":        true,
	"ENV":             true,
	"PYTHONPATH":      true,
	"PERL5LIB":        true,
	"PERL5OPT":        true,
	"RUBYOPT":         true,
	"NODE_OPTIONS":    true,
}

// SanitizeEnv filters and validates environment variables against injection attacks and poisoned keys.
func SanitizeEnv(env []string) []string {
	var clean []string
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		key := strings.TrimSpace(parts[0])
		if !validEnvKeyRegex.MatchString(key) {
			continue
		}
		if blockedEnvKeys[strings.ToUpper(key)] {
			continue
		}
		if len(parts) == 2 {
			clean = append(clean, fmt.Sprintf("%s=%s", key, parts[1]))
		} else {
			clean = append(clean, key)
		}
	}
	return clean
}

func quoteShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func formatEnvExports(env []string) string {
	sanitized := SanitizeEnv(env)
	var envPrefix strings.Builder
	for _, e := range sanitized {
		parts := strings.SplitN(e, "=", 2)
		key := parts[0]
		if len(parts) == 2 {
			envPrefix.WriteString(fmt.Sprintf("export %s=%s\n", key, quoteShellArg(parts[1])))
		} else {
			envPrefix.WriteString(fmt.Sprintf("export %s\n", key))
		}
	}
	return envPrefix.String()
}

// Config configures the ThreadDaemon.
type Config struct {
	ServerURL     string
	ListenAddress string // e.g. ":8080" for inverted connection mode
	Domain        string
	Token         string
	CACertPath    string
	Hostname      string
	Version       string
	Tags          []string
	DNSManager    *meshdns.SystemDNSManager
	MaxBackoff    time.Duration
	InitialRetry  time.Duration
}

// Agent is the deep autonomous thread daemon module managing connection resilience,
// command execution, PTY sessions, file transfers, proxying, and DNS coordination.
type Agent struct {
	cfg              Config
	dnsMgr           *meshdns.SystemDNSManager
	mu               sync.RWMutex
	actualListenAddr string
}

// New creates and initializes a new ThreadDaemon Agent.
func New(cfg Config) *Agent {
	if cfg.Domain == "" {
		cfg.Domain = version.DefaultDomain
	}
	if cfg.Version == "" {
		cfg.Version = version.Version
	}
	if cfg.Hostname == "" {
		h, _ := os.Hostname()
		cfg.Hostname = h
	}
	if cfg.InitialRetry <= 0 {
		cfg.InitialRetry = 1 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}

	dnsMgr := cfg.DNSManager
	if dnsMgr == nil {
		dnsMgr = meshdns.NewSystemDNSManager(cfg.Domain)
	}

	return &Agent{
		cfg:    cfg,
		dnsMgr: dnsMgr,
	}
}

// DNSManager returns the attached SystemDNSManager.
func (a *Agent) DNSManager() *meshdns.SystemDNSManager {
	return a.dnsMgr
}

// ListenAddr returns the actual bound listening address.
func (a *Agent) ListenAddr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.actualListenAddr != "" {
		return a.actualListenAddr
	}
	return a.cfg.ListenAddress
}

// CheckOrigin validates the incoming WebSocket request Origin header.
func (a *Agent) CheckOrigin(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		// Non-browser direct CLI or agent client
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	originHost := strings.ToLower(u.Hostname())
	if originHost == "localhost" || originHost == "127.0.0.1" || originHost == "::1" {
		return true
	}

	reqHost := req.Host
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	if strings.EqualFold(originHost, reqHost) {
		return true
	}

	domain := strings.ToLower(a.cfg.Domain)
	if domain != "" {
		if originHost == domain || strings.HasSuffix(originHost, "."+domain) {
			return true
		}
	}

	return false
}

// ListenAndServe starts a public listener for direct Inverted Connection Mode.
func (a *Agent) ListenAndServe(ctx context.Context) error {
	tlsCfg, err := pki.BuildMTLSConfig(a.cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to build TLS config for listener: %w", err)
	}

	// Enforce strict client cert validation for mTLS
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	tlsCfg.ClientCAs = tlsCfg.RootCAs

	upgrader := websocket.Upgrader{
		CheckOrigin: a.CheckOrigin,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[Agent] Direct listener upgrade error: %v", err)
			return
		}

		streamMux, err := protocol.NewStreamMultiplexer(conn, true)
		if err != nil {
			conn.Close()
			return
		}

		a.dnsMgr.SetMultiplexer(streamMux)
		router := protocol.NewRouter(streamMux.Session)
		router.HandleFunc(string(protocol.TypeExecRequest), a.HandleExec)
		router.HandleFunc(string(protocol.TypeCopyRequest), a.HandleCopy)
		router.HandleFunc(string(protocol.TypeProxyRequest), a.HandleProxy)
		
		go router.Accept()
	})

	ln, err := net.Listen("tcp", a.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to bind listen address: %w", err)
	}
	a.mu.Lock()
	a.actualListenAddr = ln.Addr().String()
	a.mu.Unlock()
	log.Printf("[Agent] Started direct listener on %s", a.actualListenAddr)

	server := &http.Server{
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return server.ServeTLS(ln, "", "")
}

// Run executes the agent daemon loop until the provided context is canceled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.dnsMgr.Start(); err != nil {
		log.Printf("[Agent] Warning: DNS manager start failed: %v", err)
	}
	defer a.dnsMgr.Teardown()

	if a.cfg.ListenAddress != "" {
		if a.cfg.ServerURL == "" || a.cfg.ServerURL == "none" {
			log.Printf("[Agent] Running in pure Inverted Mode (listener: %s)...", a.cfg.ListenAddress)
			return a.ListenAndServe(ctx)
		}
		go func() {
			if err := a.ListenAndServe(ctx); err != nil && err != context.Canceled {
				log.Printf("[Agent] ListenAndServe error: %v", err)
			}
		}()
	}

	u, err := pki.NormalizeURL(a.cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server url: %w", err)
	}

	backoff := a.cfg.InitialRetry
	sessionID := fmt.Sprintf("thread-%s-%d", a.cfg.Hostname, time.Now().UnixNano())

	for {
		select {
		case <-ctx.Done():
			log.Println("[Agent] Context canceled, stopping agent daemon...")
			return nil
		default:
		}

		err := a.dialAndServe(ctx, u, sessionID)
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			log.Printf("[Agent] Session error: %v. Reconnecting in %v...", err, backoff)
		} else {
			log.Printf("[Agent] Session closed. Reconnecting in %v...", backoff)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > a.cfg.MaxBackoff {
			backoff = a.cfg.MaxBackoff
		}
	}
}

func (a *Agent) dialAndServe(ctx context.Context, u *url.URL, sessionID string) error {
	dialer, err := pki.NewSecureDialer(a.cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to build secure TLS dialer: %w", err)
	}

	log.Printf("[Agent] Connecting to %s (mTLS enabled)...", u.String())
	conn, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.SetPingHandler(func(appData string) error {
		conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(10*time.Second))
		return nil
	})

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return fmt.Errorf("multiplexer init error: %w", err)
	}

	a.dnsMgr.SetMultiplexer(mux)

	// Send handshake
	stream, err := mux.Session.Open()
	if err != nil {
		return fmt.Errorf("failed to open handshake stream: %w", err)
	}

	hs := protocol.Handshake{
		Type:            protocol.TypeHandshake,
		SessionID:       sessionID,
		Hostname:        a.cfg.Hostname,
		Domain:          a.cfg.Domain,
		Token:           a.cfg.Token,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Version:         a.cfg.Version,
		ProtocolVersion: version.ProtocolVersion,
		Tags:            a.cfg.Tags,
	}

	b, _ := json.Marshal(hs)
	if _, err := stream.Write(b); err != nil {
		stream.Close()
		return fmt.Errorf("failed to send handshake: %w", err)
	}
	stream.Close()

	log.Println("[Agent] Handshake sent successfully. Listening for router events...")

	router := protocol.NewRouter(mux.Session)

	router.HandleFunc(string(protocol.TypeNodeSync), func(s net.Conn, env []byte) {
		defer s.Close()
		var syncMsg protocol.NodeSync
		if err := json.Unmarshal(env, &syncMsg); err == nil {
			a.dnsMgr.SyncNodes(syncMsg.Nodes, a.cfg.ServerURL)
		}
	})

	router.HandleFunc(string(protocol.TypeDNSResponse), func(s net.Conn, env []byte) {
		defer s.Close()
		var resp protocol.DNSResponse
		if err := json.Unmarshal(env, &resp); err == nil {
			a.dnsMgr.HandleDNSResponse(resp)
		}
	})

	router.HandleFunc(string(protocol.TypeExecRequest), a.HandleExec)
	router.HandleFunc(string(protocol.TypeCopyRequest), a.HandleCopy)
	router.HandleFunc(string(protocol.TypeProxyRequest), a.HandleProxy)

	errCh := make(chan error, 1)
	go func() {
		errCh <- router.Accept()
	}()

	select {
	case <-ctx.Done():
		mux.Session.Close()
		return nil
	case err := <-errCh:
		return err
	}
}

func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}

	targetPGID := pid
	if pgid, err := syscall.Getpgid(pid); err == nil {
		targetPGID = pgid
	}

	// Send SIGTERM to entire process group
	_ = syscall.Kill(-targetPGID, syscall.SIGTERM)

	// Monitor if process group exits within 500ms grace period; if not, enforce SIGKILL
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(50 * time.Millisecond)
			if err := syscall.Kill(pid, 0); err != nil {
				close(done)
				return
			}
		}
		_ = syscall.Kill(-targetPGID, syscall.SIGKILL)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(600 * time.Millisecond):
		_ = syscall.Kill(-targetPGID, syscall.SIGKILL)
	}
}

// HandleExec executes an incoming command or interactive PTY session and streams stdio frames.
func (a *Agent) HandleExec(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.ExecRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	var cmd *exec.Cmd
	if req.User != "" {
		if !validUsernameRegex.MatchString(req.User) {
			protocol.WriteFrame(stream, protocol.StreamStderr, []byte(fmt.Sprintf("invalid username %q\n", req.User)))
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		envPrefix := formatEnvExports(req.Env)
		fullCmd := envPrefix + req.Command
		cmd = exec.Command("su", "-", req.User, "-c", fullCmd)
	} else {
		cmd = exec.Command("sh", "-c", req.Command)
	}
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	sanitizedEnv := SanitizeEnv(req.Env)
	if len(sanitizedEnv) > 0 {
		cmd.Env = append(os.Environ(), sanitizedEnv...)
	}

	// Process group isolation
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if req.Detached {
		if err := cmd.Start(); err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		go func() {
			if req.TimeoutSeconds > 0 {
				timer := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
					if cmd.Process != nil {
						killProcessGroup(cmd.Process.Pid)
					}
				})
				defer timer.Stop()
			}
			_ = cmd.Wait()
		}()
		protocol.WriteFrame(stream, protocol.StreamExit, []byte("0"))
		return
	}

	var killOnce sync.Once
	killCmd := func() {
		killOnce.Do(func() {
			if cmd.Process != nil {
				killProcessGroup(cmd.Process.Pid)
			}
		})
	}
	defer killCmd()

	if req.TimeoutSeconds > 0 {
		timeoutTimer := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
			protocol.WriteFrame(stream, protocol.StreamStderr, []byte(fmt.Sprintf("\n[!] Execution timed out after %d seconds\n", req.TimeoutSeconds)))
			killCmd()
		})
		defer timeoutTimer.Stop()
	}

	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		defer func() {
			_ = ptmx.Close()
		}()

		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					if writeErr := protocol.WriteFrame(stream, protocol.StreamStdout, buf[:n]); writeErr != nil {
						killCmd()
						break
					}
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			for {
				frame, err := protocol.ReadFrame(stream)
				if err != nil {
					// Client stream terminated or disconnected
					killCmd()
					break
				}
				if frame.Type == protocol.StreamStdin {
					if _, writeErr := ptmx.Write(frame.Payload); writeErr != nil {
						break
					}
				}
			}
		}()
	} else {
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		stdin, _ := cmd.StdinPipe()

		if err := cmd.Start(); err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}

		go func() {
			defer stdout.Close()
			buf := make([]byte, 64*1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					if writeErr := protocol.WriteFrame(stream, protocol.StreamStdout, buf[:n]); writeErr != nil {
						killCmd()
						break
					}
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			defer stderr.Close()
			buf := make([]byte, 64*1024)
			for {
				n, err := stderr.Read(buf)
				if n > 0 {
					if writeErr := protocol.WriteFrame(stream, protocol.StreamStderr, buf[:n]); writeErr != nil {
						killCmd()
						break
					}
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			defer stdin.Close()
			for {
				frame, err := protocol.ReadFrame(stream)
				if err != nil {
					// Client stream terminated or disconnected
					killCmd()
					break
				}
				if frame.Type == protocol.StreamStdin {
					if _, writeErr := stdin.Write(frame.Payload); writeErr != nil {
						break
					}
				}
			}
		}()
	}

	err := cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	protocol.WriteFrame(stream, protocol.StreamExit, []byte(strconv.Itoa(exitCode)))
}

// HandleCopy handles tar streaming upload or download requests.
func (a *Agent) HandleCopy(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.CopyRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	if req.Direction == "download" {
		if err := protocol.CreateTar(stream, req.RemotePath); err != nil {
			log.Println("[Agent] Error creating tar for download:", err)
		}
	} else if req.Direction == "upload" {
		if err := protocol.ValidateDestinationPath(req.RemotePath); err != nil {
			log.Printf("[Agent] Blocked upload to restricted destination %q: %v\n", req.RemotePath, err)
			return
		}
		if err := protocol.ExtractTar(stream, req.RemotePath); err != nil {
			log.Println("[Agent] Error extracting tar for upload:", err)
		}
	}
}

// HandleProxy validates destination and proxies incoming TCP traffic.
func (a *Agent) HandleProxy(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.ProxyRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	targetAddr, err := protocol.ValidateProxyDestination(req.TargetHost, req.TargetPort)
	if err != nil {
		log.Println("[Agent] Blocked proxy request:", err)
		return
	}

	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Println("[Agent] Thread proxy dial error:", err)
		return
	}
	defer conn.Close()

	protocol.Proxy(stream, conn)
}

