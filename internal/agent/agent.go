package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"fabric/internal/meshdns"
	"fabric/internal/pki"
	"fabric/internal/protocol"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// Config configures the NodeAgent daemon.
type Config struct {
	ServerURL    string
	Domain       string
	Token        string
	CACertPath   string
	Hostname     string
	Version      string
	DNSManager   *meshdns.SystemDNSManager
	MaxBackoff   time.Duration
	InitialRetry time.Duration
}

// Agent is the deep autonomous node daemon module managing connection resilience,
// command execution, PTY sessions, file transfers, proxying, and DNS coordination.
type Agent struct {
	cfg    Config
	dnsMgr *meshdns.SystemDNSManager
}

// New creates and initializes a new NodeAgent.
func New(cfg Config) *Agent {
	if cfg.Domain == "" {
		cfg.Domain = "fabric.mesh"
	}
	if cfg.Version == "" {
		cfg.Version = "1.0.0"
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

// Run executes the agent daemon loop until the provided context is canceled.
func (a *Agent) Run(ctx context.Context) error {
	u, err := pki.NormalizeURL(a.cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server url: %w", err)
	}

	if err := a.dnsMgr.Start(); err != nil {
		log.Printf("[Agent] Warning: DNS manager start failed: %v", err)
	}
	defer a.dnsMgr.Teardown()

	backoff := a.cfg.InitialRetry
	sessionID := fmt.Sprintf("node-%s-%d", a.cfg.Hostname, time.Now().UnixNano())

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
	dialer := websocket.DefaultDialer
	if u.Scheme == "wss" {
		var err error
		dialer, err = pki.NewWSSDialer(a.cfg.CACertPath)
		if err != nil {
			log.Printf("[Agent] Warning: TLS dialer error: %v", err)
			dialer = websocket.DefaultDialer
		}
	}

	log.Printf("[Agent] Connecting to %s...", u.String())
	conn, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return pki.FormatTLSError(err)
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
		Type:      protocol.TypeHandshake,
		SessionID: sessionID,
		Hostname:  a.cfg.Hostname,
		Domain:    a.cfg.Domain,
		Token:     a.cfg.Token,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   a.cfg.Version,
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

// HandleExec executes an incoming command or interactive PTY session and streams stdio frames.
func (a *Agent) HandleExec(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.ExecRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	command := req.Command
	if req.User != "" {
		command = fmt.Sprintf("su - %s -c %q", req.User, req.Command)
	}
	cmd := exec.Command("sh", "-c", command)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	if len(req.Env) > 0 {
		cmd.Env = append(os.Environ(), req.Env...)
	}

	if req.Detached {
		if err := cmd.Start(); err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		go func() {
			cmd.Wait()
		}()
		protocol.WriteFrame(stream, protocol.StreamExit, []byte("0"))
		return
	}

	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		defer ptmx.Close()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStdout, buf[:n])
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
					break
				}
				if frame.Type == protocol.StreamStdin {
					ptmx.Write(frame.Payload)
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
			buf := make([]byte, 1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStdout, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := stderr.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStderr, buf[:n])
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
					break
				}
				if frame.Type == protocol.StreamStdin {
					stdin.Write(frame.Payload)
				}
			}
			stdin.Close()
		}()
	}

	cmd.Wait()
	protocol.WriteFrame(stream, protocol.StreamExit, []byte("0"))
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
		resp := protocol.ProxyResponse{
			Type:    protocol.TypeProxyResponse,
			Success: false,
			Error:   err.Error(),
		}
		if b, marshalErr := json.Marshal(resp); marshalErr == nil {
			stream.Write(b)
		}
		return
	}

	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Println("[Agent] Node proxy dial error:", err)
		resp := protocol.ProxyResponse{
			Type:    protocol.TypeProxyResponse,
			Success: false,
			Error:   err.Error(),
		}
		if b, marshalErr := json.Marshal(resp); marshalErr == nil {
			stream.Write(b)
		}
		return
	}
	defer conn.Close()

	protocol.Proxy(stream, conn)
}
