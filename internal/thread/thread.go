package thread

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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"fabric/internal/dns"
	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/version"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

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
	DNSManager    *dns.FabricDNSManager
	Sandbox       ExecutionSandbox
	MaxBackoff    time.Duration
	InitialRetry  time.Duration
}

// ThreadDaemon is the deep autonomous thread daemon module managing connection resilience,
// command execution, PTY sessions, file transfers, proxying, and DNS coordination.
type ThreadDaemon struct {
	cfg              Config
	dnsMgr           *dns.FabricDNSManager
	sandbox          ExecutionSandbox
	mu               sync.RWMutex
	actualListenAddr string
}

// Agent is a backward-compatible alias for ThreadDaemon.
type Agent = ThreadDaemon

// New creates and initializes a new ThreadDaemon.
func New(cfg Config) *ThreadDaemon {
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
		dnsMgr = dns.NewFabricDNSManager(cfg.Domain)
	}

	sandbox := cfg.Sandbox
	if sandbox == nil {
		sandbox = NewExecutionSandbox(SandboxConfig{})
	}

	return &ThreadDaemon{
		cfg:     cfg,
		dnsMgr:  dnsMgr,
		sandbox: sandbox,
	}
}

// Sandbox returns the attached ExecutionSandbox.
func (t *ThreadDaemon) Sandbox() ExecutionSandbox {
	return t.sandbox
}

// DNSManager returns the attached FabricDNSManager.
func (t *ThreadDaemon) DNSManager() *dns.FabricDNSManager {
	return t.dnsMgr
}

// ListenAddr returns the actual bound listening address.
func (t *ThreadDaemon) ListenAddr() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.actualListenAddr != "" {
		return t.actualListenAddr
	}
	return t.cfg.ListenAddress
}

// CheckOrigin validates the incoming WebSocket request Origin header.
func (t *ThreadDaemon) CheckOrigin(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		// Non-browser direct CLI or thread client
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

	domain := strings.ToLower(t.cfg.Domain)
	if domain != "" {
		if originHost == domain || strings.HasSuffix(originHost, "."+domain) {
			return true
		}
	}

	return false
}

// ListenAndServe starts a public listener for direct Inverted Connection Mode.
func (t *ThreadDaemon) ListenAndServe(ctx context.Context) error {
	tlsCfg, err := pki.BuildMTLSConfig(t.cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to build TLS config for listener: %w", err)
	}

	// Enforce strict client cert validation for mTLS
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	tlsCfg.ClientCAs = tlsCfg.RootCAs

	upgrader := websocket.Upgrader{
		CheckOrigin: t.CheckOrigin,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[Thread] Direct listener upgrade error: %v", err)
			return
		}

		streamMux, err := protocol.NewStreamMultiplexer(conn, true)
		if err != nil {
			conn.Close()
			return
		}

		t.dnsMgr.SetMultiplexer(streamMux)
		router := protocol.NewRouter(streamMux.Session)
		router.HandleFunc(string(protocol.TypeExecRequest), t.HandleExec)
		router.HandleFunc(string(protocol.TypeCopyRequest), t.HandleCopy)
		router.HandleFunc(string(protocol.TypeProxyRequest), t.HandleProxy)

		go router.Accept()
	})

	ln, err := net.Listen("tcp", t.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to bind listen address: %w", err)
	}
	t.mu.Lock()
	t.actualListenAddr = ln.Addr().String()
	t.mu.Unlock()
	log.Printf("[Thread] Started direct listener on %s", t.actualListenAddr)

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

// Run executes the thread daemon loop until the provided context is canceled.
func (t *ThreadDaemon) Run(ctx context.Context) error {
	if err := t.dnsMgr.Start(); err != nil {
		log.Printf("[Thread] Warning: DNS manager start failed: %v", err)
	}
	defer t.dnsMgr.Teardown()

	if t.cfg.ListenAddress != "" {
		if t.cfg.ServerURL == "" || t.cfg.ServerURL == "none" {
			log.Printf("[Thread] Running in pure Inverted Mode (listener: %s)...", t.cfg.ListenAddress)
			return t.ListenAndServe(ctx)
		}
		go func() {
			if err := t.ListenAndServe(ctx); err != nil && err != context.Canceled {
				log.Printf("[Thread] ListenAndServe error: %v", err)
			}
		}()
	}

	u, err := pki.NormalizeURL(t.cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server url: %w", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}

	backoff := t.cfg.InitialRetry
	sessionID := fmt.Sprintf("thread-%s-%d", t.cfg.Hostname, time.Now().UnixNano())

	for {
		select {
		case <-ctx.Done():
			log.Println("[Thread] Context canceled, stopping thread daemon...")
			return nil
		default:
		}

		err := t.dialAndServe(ctx, u, sessionID)
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			log.Printf("[Thread] Session error: %v. Reconnecting in %v...", err, backoff)
		} else {
			log.Printf("[Thread] Session closed. Reconnecting in %v...", backoff)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > t.cfg.MaxBackoff {
			backoff = t.cfg.MaxBackoff
		}
	}
}

func (t *ThreadDaemon) dialAndServe(ctx context.Context, u *url.URL, sessionID string) error {
	dialer, err := pki.NewSecureDialer(t.cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to build secure TLS dialer: %w", err)
	}

	header := http.Header{}
	if t.cfg.Token != "" {
		header.Add("Authorization", "Bearer "+t.cfg.Token)
	}

	log.Printf("[Thread] Connecting to %s (mTLS enabled)...", u.String())
	conn, _, err := dialer.DialContext(ctx, u.String(), header)
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

	t.dnsMgr.SetMultiplexer(mux)

	// Send handshake
	stream, err := mux.Session.Open()
	if err != nil {
		return fmt.Errorf("failed to open handshake stream: %w", err)
	}

	hs := protocol.Handshake{
		Type:            protocol.TypeHandshake,
		SessionID:       sessionID,
		Hostname:        t.cfg.Hostname,
		Domain:          t.cfg.Domain,
		Token:           t.cfg.Token,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Version:         t.cfg.Version,
		ProtocolVersion: version.ProtocolVersion,
		Tags:            t.cfg.Tags,
	}

	b, _ := json.Marshal(hs)
	if _, err := stream.Write(b); err != nil {
		stream.Close()
		return fmt.Errorf("failed to send handshake: %w", err)
	}
	stream.Close()

	log.Println("[Thread] Handshake sent successfully. Listening for router events...")

	router := protocol.NewRouter(mux.Session)

	router.HandleFunc(string(protocol.TypeThreadSync), func(s net.Conn, env []byte) {
		defer s.Close()
		var syncMsg protocol.ThreadSync
		if err := json.Unmarshal(env, &syncMsg); err == nil {
			threadsToSync := syncMsg.Threads
			if len(threadsToSync) > 0 && t.dnsMgr != nil {
				t.dnsMgr.SyncThreads(threadsToSync, t.cfg.ServerURL)
			}
		}
	})

	router.HandleFunc(string(protocol.TypeNodeSync), func(s net.Conn, env []byte) {
		defer s.Close()
		var syncMsg protocol.NodeSync
		if err := json.Unmarshal(env, &syncMsg); err != nil {
			return
		}
		threadsToSync := syncMsg.Threads
		if len(threadsToSync) == 0 {
			threadsToSync = syncMsg.Nodes
		}
		if len(threadsToSync) > 0 && t.dnsMgr != nil {
			t.dnsMgr.SyncThreads(threadsToSync, t.cfg.ServerURL)
		}
	})

	router.HandleFunc(string(protocol.TypeDNSResponse), func(s net.Conn, env []byte) {
		defer s.Close()
		var resp protocol.DNSResponse
		if err := json.Unmarshal(env, &resp); err == nil {
			t.dnsMgr.HandleDNSResponse(resp)
		}
	})

	router.HandleFunc(string(protocol.TypeExecRequest), t.HandleExec)
	router.HandleFunc(string(protocol.TypeCopyRequest), t.HandleCopy)
	router.HandleFunc(string(protocol.TypeProxyRequest), t.HandleProxy)

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

// HandleExec executes an incoming command or interactive PTY session and streams stdio frames.
func (t *ThreadDaemon) HandleExec(stream net.Conn, env []byte) {
	defer stream.Close()

	var streamMu sync.Mutex
	writeFrame := func(streamType protocol.StreamType, payload []byte) error {
		streamMu.Lock()
		defer streamMu.Unlock()
		return protocol.WriteFrame(stream, streamType, payload)
	}

	var req protocol.ExecRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	cmd, err := t.sandbox.PrepareCmd(req)
	if err != nil {
		writeFrame(protocol.StreamStderr, []byte(fmt.Sprintf("%v\n", err)))
		writeFrame(protocol.StreamExit, []byte("1"))
		return
	}

	if req.Detached {
		if err := cmd.Start(); err != nil {
			writeFrame(protocol.StreamExit, []byte("1"))
			return
		}
		go func() {
			if req.TimeoutSeconds > 0 {
				timer := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
					if cmd.Process != nil {
						_ = t.sandbox.KillProcessGroup(cmd.Process.Pid)
					}
				})
				defer timer.Stop()
			}
			_ = cmd.Wait()
		}()
		writeFrame(protocol.StreamExit, []byte("0"))
		return
	}

	var procMu sync.Mutex
	var procPid int

	var killOnce sync.Once
	killCmd := func() {
		killOnce.Do(func() {
			procMu.Lock()
			pid := procPid
			procMu.Unlock()
			if pid > 0 {
				_ = t.sandbox.KillProcessGroup(pid)
			}
		})
	}
	defer killCmd()

	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			writeFrame(protocol.StreamExit, []byte("1"))
			return
		}
		procMu.Lock()
		if cmd.Process != nil {
			procPid = cmd.Process.Pid
		}
		procMu.Unlock()

		if req.TimeoutSeconds > 0 {
			timeoutTimer := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
				writeFrame(protocol.StreamStderr, []byte(fmt.Sprintf("\n[!] Execution timed out after %d seconds\n", req.TimeoutSeconds)))
				killCmd()
			})
			defer timeoutTimer.Stop()
		}

		defer func() {
			_ = ptmx.Close()
		}()

		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					if writeErr := writeFrame(protocol.StreamStdout, buf[:n]); writeErr != nil {
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
			writeFrame(protocol.StreamExit, []byte("1"))
			return
		}
		procMu.Lock()
		if cmd.Process != nil {
			procPid = cmd.Process.Pid
		}
		procMu.Unlock()

		if req.TimeoutSeconds > 0 {
			timeoutTimer := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
				writeFrame(protocol.StreamStderr, []byte(fmt.Sprintf("\n[!] Execution timed out after %d seconds\n", req.TimeoutSeconds)))
				killCmd()
			})
			defer timeoutTimer.Stop()
		}

		var stdioWg sync.WaitGroup
		stdioWg.Add(2)

		go func() {
			defer stdioWg.Done()
			defer stdout.Close()
			buf := make([]byte, 64*1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					if writeErr := writeFrame(protocol.StreamStdout, buf[:n]); writeErr != nil {
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
			defer stdioWg.Done()
			defer stderr.Close()
			buf := make([]byte, 64*1024)
			for {
				n, err := stderr.Read(buf)
				if n > 0 {
					if writeErr := writeFrame(protocol.StreamStderr, buf[:n]); writeErr != nil {
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

		stdioWg.Wait()
		err = cmd.Wait()
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	writeFrame(protocol.StreamExit, []byte(strconv.Itoa(exitCode)))
}

// HandleCopy handles tar streaming upload or download requests.
func (t *ThreadDaemon) HandleCopy(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.CopyRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	if req.Direction == "download" {
		if err := protocol.CreateTar(stream, req.RemotePath); err != nil {
			log.Println("[Thread] Error creating tar for download:", err)
		}
	} else if req.Direction == "upload" {
		if err := protocol.ValidateDestinationPath(req.RemotePath); err != nil {
			log.Printf("[Thread] Blocked upload to restricted destination %q: %v\n", req.RemotePath, err)
			return
		}
		if err := protocol.ExtractTar(stream, req.RemotePath); err != nil {
			log.Println("[Thread] Error extracting tar for upload:", err)
		}
	}
}

// HandleProxy validates destination and proxies incoming TCP traffic.
func (t *ThreadDaemon) HandleProxy(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.ProxyRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	targetAddr, err := protocol.ValidateProxyDestination(req.TargetHost, req.TargetPort)
	if err != nil {
		log.Println("[Thread] Blocked proxy request:", err)
		return
	}

	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Println("[Thread] Thread proxy dial error:", err)
		return
	}
	defer conn.Close()

	protocol.Proxy(stream, conn)
}
