package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fabric/internal/pki"
	"fabric/internal/protocol"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// ExecOptions holds parameters for remote command execution.
type ExecOptions struct {
	Target      string
	Command     string
	AllocatePTY bool
	Interactive bool
	Detached    bool
	Env         []string
	WorkDir     string
	User        string
}

// Client provides deep operational methods to communicate with a Fabric Socket and mesh nodes.
type Client struct {
	Config        *Config
	DirectAddress string
}

// NewClient creates a new Mesh Client with the given CLI configuration.
func NewClient(cfg *Config) *Client {
	return &Client{Config: cfg}
}

func (c *Client) caCertPath() string {
	if c != nil && c.Config != nil {
		return c.Config.CACert
	}
	return ""
}

// DialWebSocket dials the central socket control plane or a direct node.
func (c *Client) DialWebSocket() (*websocket.Conn, error) {
	targetHost := c.Config.Host
	if c.DirectAddress != "" {
		targetHost = c.DirectAddress
		if !strings.Contains(targetHost, "://") {
			targetHost = "wss://" + targetHost
		}
	}

	u, err := pki.NormalizeURL(targetHost)
	if err != nil {
		return nil, fmt.Errorf("invalid host url: %w", err)
	}

	header := http.Header{}
	header.Add("Authorization", "Bearer "+c.Config.Token)

	dialer := websocket.DefaultDialer
	if u.Scheme == "wss" {
		var err error
		dialer, err = pki.NewWSSDialer(c.caCertPath())
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		if c.DirectAddress != "" {
			// In direct mode, the node uses an ephemeral server cert
			dialer.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	conn, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		return nil, pki.FormatTLSError(fmt.Errorf("websocket dial (%s): %w", u.String(), err))
	}
	return conn, nil
}

// DoHTTP performs an authenticated HTTP REST request to the Socket.
func (c *Client) DoHTTP(method, path string, body interface{}) (*http.Response, error) {
	u, err := pki.NormalizeURL(c.Config.Host)
	if err != nil {
		return nil, err
	}

	scheme := "http"
	if u.Scheme == "wss" {
		scheme = "https"
	}
	u.Scheme = scheme
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+c.Config.Token)

	httpClient := http.DefaultClient
	if scheme == "https" {
		tlsCfg, err := pki.BuildClientTLSConfig(c.caCertPath())
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
			Timeout: 30 * time.Second,
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, pki.FormatTLSError(err)
	}
	return resp, nil
}

// ListNodes retrieves metadata for all connected mesh nodes.
func (c *Client) ListNodes() ([]protocol.NodeMetadata, error) {
	resp, err := c.DoHTTP("GET", "/nodes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list nodes: HTTP %s", resp.Status)
	}

	var nodes []protocol.NodeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// GetNode retrieves metadata for a single mesh node.
func (c *Client) GetNode(hostname string) (*protocol.NodeMetadata, error) {
	resp, err := c.DoHTTP("GET", "/nodes/"+hostname, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("node not found: %s", hostname)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get node %s: HTTP %s", hostname, resp.Status)
	}

	var meta protocol.NodeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// Execute opens a multiplexed stream to the target node and executes a command with standard I/O streaming.
func (c *Client) Execute(opts ExecOptions, in io.Reader, out, errOut io.Writer) error {
	conn, err := c.DialWebSocket()
	if err != nil {
		return err
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return err
	}
	defer stream.Close()

	sessionID := fmt.Sprintf("sess-%d", time.Now().UnixNano())

	req := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
		SessionID:      sessionID,
		TargetHostname: opts.Target,
		Command:        opts.Command,
		AllocatePTY:    opts.AllocatePTY,
		Interactive:    opts.Interactive,
		Detached:       opts.Detached,
		Env:            opts.Env,
		WorkDir:        opts.WorkDir,
		User:           opts.User,
	}

	b, _ := json.Marshal(req)
	if _, err := stream.Write(b); err != nil {
		return err
	}

	if opts.Detached {
		fmt.Fprintln(out, sessionID)
		return nil
	}

	if opts.AllocatePTY && in != nil {
		if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
			oldState, err := term.MakeRaw(int(file.Fd()))
			if err == nil {
				defer term.Restore(int(file.Fd()), oldState)
			}
		}
	}

	if (opts.Interactive || opts.AllocatePTY) && in != nil {
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := in.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStdin, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()
	}

	for {
		frame, err := protocol.ReadFrame(stream)
		if err != nil {
			break
		}

		switch frame.Type {
		case protocol.StreamStdout:
			if out != nil {
				out.Write(frame.Payload)
			}
		case protocol.StreamStderr:
			if errOut != nil {
				errOut.Write(frame.Payload)
			}
		case protocol.StreamExit:
			exitStr := string(frame.Payload)
			if exitStr != "0" {
				return fmt.Errorf("exit code %s", exitStr)
			}
			return nil
		}
	}
	return nil
}

// Upload streams a local file or directory as a Tar archive to a remote node destination.
func (c *Client) Upload(targetNode, localPath, remotePath string) error {
	conn, err := c.DialWebSocket()
	if err != nil {
		return fmt.Errorf("failed to connect to socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return err
	}
	defer stream.Close()

	req := protocol.CopyRequest{
		Type:           protocol.TypeCopyRequest,
		TransferID:     fmt.Sprintf("xfer-%d", time.Now().UnixNano()),
		TargetHostname: targetNode,
		Direction:      "upload",
		RemotePath:     remotePath,
	}

	b, _ := json.Marshal(req)
	stream.Write(b)

	if err := protocol.CreateTar(stream, localPath); err != nil {
		return fmt.Errorf("failed to create upload archive: %w", err)
	}
	return nil
}

// Download streams a remote node path as a Tar archive and extracts it to a local destination.
func (c *Client) Download(targetNode, remotePath, localPath string) error {
	conn, err := c.DialWebSocket()
	if err != nil {
		return fmt.Errorf("failed to connect to socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return err
	}
	defer stream.Close()

	req := protocol.CopyRequest{
		Type:           protocol.TypeCopyRequest,
		TransferID:     fmt.Sprintf("xfer-%d", time.Now().UnixNano()),
		TargetHostname: targetNode,
		Direction:      "download",
		RemotePath:     remotePath,
	}

	b, _ := json.Marshal(req)
	stream.Write(b)

	if err := protocol.ExtractTar(stream, localPath); err != nil {
		return fmt.Errorf("failed to extract download archive: %w", err)
	}
	return nil
}

// ForwardPort binds a local port and forwards incoming TCP connections to the remote node.
func (c *Client) ForwardPort(targetNode string, localPort, remotePort int) error {
	conn, err := c.DialWebSocket()
	if err != nil {
		return fmt.Errorf("failed to dial socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return fmt.Errorf("multiplexer error: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to bind local port %d: %w", localPort, err)
	}
	defer ln.Close()

	fmt.Printf("Forwarding 127.0.0.1:%d -> %s:%d (Ctrl+C to stop)...\n", localPort, targetNode, remotePort)

	for {
		localConn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			defer conn.Close()

			stream, err := mux.Session.Open()
			if err != nil {
				return
			}
			defer stream.Close()

			req := protocol.ProxyRequest{
				Type:           protocol.TypeProxyRequest,
				TargetHostname: targetNode,
				TargetPort:     remotePort,
			}
			b, _ := json.Marshal(req)
			stream.Write(b)

			protocol.Proxy(stream, conn)
		}(localConn)
	}
}

// ParsePortSpec helper parses LOCAL:REMOTE port spec string.
func ParsePortSpec(spec string) (int, int, error) {
	parts := strings.Split(spec, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port specification %q, expected LOCAL:REMOTE (e.g. 8080:80)", spec)
	}
	localPort, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid local port: %w", err)
	}
	remotePort, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid remote port: %w", err)
	}
	return localPort, remotePort, nil
}
