package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/wireguard"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// ExecOptions holds parameters for remote command execution across single nodes or entire fleets.
type ExecOptions struct {
	Target      string
	Command     string
	AllocatePTY bool
	Interactive bool
	Detached    bool
	Env         []string
	WorkDir     string
	User        string
	// Fleet parameters
	All         bool
	Tag         string
	Concurrency int
}

// ThreadExecResult stores execution telemetry for a single targeted thread.
type ThreadExecResult struct {
	Thread   string
	Node     string
	Success  bool
	ExitCode string
	Duration time.Duration
	Error    error
}

// NodeExecResult is a backward-compatible alias for ThreadExecResult.
type NodeExecResult = ThreadExecResult

// FleetThreadResult aggregates execution results across all targeted threads.
type FleetThreadResult struct {
	Results        []ThreadExecResult
	Total          int
	SucceededCount int
	FailedCount    int
	HasFailure     bool
}

// FleetResult is a backward-compatible alias for FleetThreadResult.
type FleetResult = FleetThreadResult

// MeshClient is a canonical alias for Client.
type MeshClient = Client

// LinePrefixedWriter buffers streamed output chunks and prints complete lines prefixed with the node identifier.
type LinePrefixedWriter struct {
	prefix string
	out    io.Writer
	mu     *sync.Mutex
	buf    bytes.Buffer
}

// NewLinePrefixedWriter creates a thread-safe line prefix writer for node output streaming.
func NewLinePrefixedWriter(prefix string, out io.Writer, mu *sync.Mutex) *LinePrefixedWriter {
	return &LinePrefixedWriter{
		prefix: prefix,
		out:    out,
		mu:     mu,
	}
}

func (w *LinePrefixedWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n = len(p)
	w.buf.Write(p)

	for {
		line, err := w.buf.ReadBytes('\n')
		if err != nil {
			w.buf.Write(line)
			break
		}
		fmt.Fprintf(w.out, "[%s] %s", w.prefix, string(line))
	}
	return n, nil
}

func (w *LinePrefixedWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buf.Len() > 0 {
		fmt.Fprintf(w.out, "[%s] %s\n", w.prefix, w.buf.String())
		w.buf.Reset()
	}
}

// Client provides deep operational methods to communicate with a Fabric Socket and mesh nodes.
type Client struct {
	Config        *Config
	DirectAddress string
}

// NewClient creates a new Mesh Client with the given CLI configuration.
func NewClient(cfg *Config) *Client {
	return &Client{
		Config:        cfg,
		DirectAddress: cfg.DirectAddress,
	}
}

func (c *Client) caCertPath() string {
	if c != nil && c.Config != nil {
		return c.Config.CACert
	}
	return ""
}

// DialWebSocket dials the central socket control plane or a direct node.
func (c *Client) DialWebSocket() (*websocket.Conn, error) {
	return c.DialWebSocketForNode("")
}

// DialWebSocketForNode dials the target node directly if registered or overrides direct address, otherwise dials socket.
func (c *Client) DialWebSocketForNode(targetNode string) (*websocket.Conn, error) {
	targetHost := c.Config.Host
	if c.DirectAddress != "" {
		targetHost = c.DirectAddress
		if !strings.Contains(targetHost, "://") {
			targetHost = "wss://" + targetHost
		}
	} else if targetNode != "" && c.Config != nil {
		if entry, ok := c.Config.GetDirectThread(targetNode); ok && entry.Address != "" {
			targetHost = entry.Address
		}
		if !strings.Contains(targetHost, "://") {
			targetHost = "wss://" + targetHost
		}
	}

	u, err := pki.NormalizeURL(targetHost)
	if err != nil {
		return nil, fmt.Errorf("invalid host url: %w", err)
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}

	header := http.Header{}
	header.Add("Authorization", "Bearer "+c.Config.Token)

	dialer, err := pki.NewSecureDialer(c.caCertPath())
	if err != nil {
		return nil, fmt.Errorf("failed to configure secure TLS dialer: %w", err)
	}

	conn, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial (%s): %w", u.String(), err)
	}
	return conn, nil
}

// DoHTTP performs an authenticated HTTP REST request to the Socket.
func (c *Client) DoHTTP(method, path string, body interface{}) (*http.Response, error) {
	u, err := pki.NormalizeURL(c.Config.Host)
	if err != nil {
		return nil, err
	}

	u.Scheme = "https"
	basePath := strings.TrimSuffix(u.Path, "/ws")
	basePath = strings.TrimRight(basePath, "/")
	u.Path = basePath + "/" + strings.TrimLeft(path, "/")

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+c.Config.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	tlsCfg, err := pki.BuildMTLSConfig(c.caCertPath())
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		Timeout: 30 * time.Second,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, pki.FormatTLSError(err)
	}
	return resp, nil
}

// ListPeers retrieves all connected peer gateways from the fabric server.
func (c *Client) ListPeers() ([]protocol.GatewayPeerInfo, error) {
	resp, err := c.DoHTTP("GET", "/peers", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list peers: HTTP %s", resp.Status)
	}

	var peers []protocol.GatewayPeerInfo
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, err
	}
	return peers, nil
}

// GetPeer retrieves telemetry for a single peer gateway.
func (c *Client) GetPeer(gatewayID string) (*protocol.GatewayPeerInfo, error) {
	resp, err := c.DoHTTP("GET", "/peers/"+gatewayID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("peer server '%s' not found", gatewayID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get peer %s: HTTP %s", gatewayID, resp.Status)
	}

	var info protocol.GatewayPeerInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// AddPeer initiates a peer connection to the given endpoint.
func (c *Client) AddPeer(endpoint string) error {
	resp, err := c.DoHTTP("POST", "/peers", map[string]string{"endpoint": endpoint})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add peer: HTTP %s", resp.Status)
	}
	return nil
}

// RemovePeer disconnects a peer gateway.
func (c *Client) RemovePeer(gatewayID string) error {
	resp, err := c.DoHTTP("DELETE", "/peers/"+gatewayID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove peer %s: HTTP %s", gatewayID, resp.Status)
	}
	return nil
}

// DeviceRegistration represents the response from registering a WireGuard device.
type DeviceRegistration struct {
	Name            string    `json:"name"`
	PublicKey       string    `json:"public_key"`
	PresharedKey    string    `json:"preshared_key,omitempty"`
	VirtualIP       string    `json:"virtual_ip"`
	AllowedIPs      []string  `json:"allowed_ips"`
	DNS             string    `json:"dns"`
	ServerPublicKey string    `json:"server_public_key"`
	ServerEndpoint  string    `json:"server_endpoint"`
	CreatedAt       time.Time `json:"created_at"`
}

// ListDevices queries the server for all registered WireGuard devices.
func (c *Client) ListDevices() ([]wireguard.DeviceEntry, error) {
	resp, err := c.DoHTTP("GET", "/api/v1/devices", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list devices: HTTP %s", resp.Status)
	}

	var devices []wireguard.DeviceEntry
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, err
	}
	return devices, nil
}

// GetDevice queries the server for a specific device by name.
func (c *Client) GetDevice(name string) (*wireguard.DeviceEntry, error) {
	resp, err := c.DoHTTP("GET", "/api/v1/devices/"+name, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("device '%s' not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get device %s: HTTP %s", name, resp.Status)
	}

	var dev wireguard.DeviceEntry
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return nil, err
	}
	return &dev, nil
}

// RegisterDevice registers a new WireGuard client device with the server.
func (c *Client) RegisterDevice(name, pubKey, psk string) (*DeviceRegistration, error) {
	body := map[string]string{
		"name":       name,
		"public_key": pubKey,
	}
	if psk != "" {
		body["preshared_key"] = psk
	}

	resp, err := c.DoHTTP("POST", "/api/v1/devices", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to register device: HTTP %s (%s)", resp.Status, strings.TrimSpace(string(respBytes)))
	}

	var reg DeviceRegistration
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

// RemoveDevice removes a registered WireGuard device from the server.
func (c *Client) RemoveDevice(name string) error {
	resp, err := c.DoHTTP("DELETE", "/api/v1/devices/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove device %s: HTTP %s", name, resp.Status)
	}
	return nil
}

// ListThreads retrieves metadata for all connected threads in the Fabric, merging direct registered threads.
func (c *Client) ListThreads() ([]protocol.ThreadMetadata, error) {
	var threads []protocol.ThreadMetadata
	var socketErr error
	var socketThread *protocol.ThreadMetadata

	socketHost := "localhost:8443"
	socketDomain := "fabric.mesh"
	if c.Config != nil && c.Config.Host != "" {
		if u, parseErr := pki.NormalizeURL(c.Config.Host); parseErr == nil {
			socketHost = u.Host
		}
	}

	// Try GET /threads first, fallback to GET /nodes on 404
	resp, err := c.DoHTTP("GET", "/threads", nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&threads)
		} else if resp.StatusCode == http.StatusNotFound {
			// Fallback to /nodes
			if nResp, nErr := c.DoHTTP("GET", "/nodes", nil); nErr == nil {
				defer nResp.Body.Close()
				if nResp.StatusCode == http.StatusOK {
					_ = json.NewDecoder(nResp.Body).Decode(&threads)
				} else {
					socketErr = fmt.Errorf("failed to list threads: HTTP %s", nResp.Status)
				}
			} else {
				socketErr = nErr
			}
		} else {
			socketErr = fmt.Errorf("failed to list threads: HTTP %s", resp.Status)
		}
	} else {
		// Try /nodes fallback on connection failure or other error
		if nResp, nErr := c.DoHTTP("GET", "/nodes", nil); nErr == nil {
			defer nResp.Body.Close()
			if nResp.StatusCode == http.StatusOK {
				_ = json.NewDecoder(nResp.Body).Decode(&threads)
				socketErr = nil
			} else {
				socketErr = fmt.Errorf("failed to list threads: HTTP %s", nResp.Status)
			}
		} else {
			socketErr = err
		}
	}

	// Always probe socket /version to check if socket control plane is alive
	if verResp, verErr := c.DoHTTP("GET", "/version", nil); verErr == nil {
		defer verResp.Body.Close()
		if verResp.StatusCode == http.StatusOK {
			var verInfo struct {
				Version string `json:"version"`
				Domain  string `json:"domain"`
			}
			if json.NewDecoder(verResp.Body).Decode(&verInfo) == nil && verInfo.Domain != "" {
				socketDomain = verInfo.Domain
			}

			socketThread = &protocol.ThreadMetadata{
				ID:          "socket",
				Hostname:    "socket",
				RemoteIP:    socketHost,
				Status:      "online [control-plane]",
				Tags:        []string{"relay", "control-plane"},
				Domain:      socketDomain,
				ConnectedAt: time.Now().UTC().Format(time.RFC3339),
			}
		}
	}

	// Merge direct threads from local configuration
	directThreads := c.Config.ListDirectThreads()
	if len(directThreads) > 0 {
		seen := make(map[string]bool)
		seenAddr := make(map[string]bool)
		for _, n := range threads {
			seen[n.Hostname] = true
			seenAddr[n.RemoteIP] = true
		}
		for name, entry := range directThreads {
			// Skip FQDN duplicates in listing if base hostname or address is already listed
			if strings.Count(name, ".") > 1 && entry.Hostname != "" && name != entry.Hostname {
				continue
			}
			displayHost := entry.Hostname
			if displayHost == "" {
				displayHost = name
			}
			if !seen[displayHost] && !seenAddr[entry.Address] {
				seen[displayHost] = true
				seenAddr[entry.Address] = true

				domain := entry.Domain
				if domain == "" {
					domain = "fabric.mesh"
				}
				osName := entry.OS
				if osName == "" {
					osName = "linux"
				}

				threads = append(threads, protocol.ThreadMetadata{
					ID:          "direct-" + displayHost,
					Hostname:    displayHost,
					RemoteIP:    entry.Address,
					Status:      "online [MODE: remote]",
					OS:          osName,
					Arch:        entry.Arch,
					Tags:        entry.Tags,
					Domain:      domain,
					ConnectedAt: entry.RegisteredAt.Format(time.RFC3339),
				})
			}
		}
	}

	if socketThread == nil {
		if c.Config != nil && c.Config.Host != "" && c.Config.Host != "wss://localhost:8443/ws" && c.Config.Host != "localhost:8443" {
			socketThread = &protocol.ThreadMetadata{
				ID:       "socket",
				Hostname: "socket",
				RemoteIP: socketHost,
				Status:   "unreachable [control-plane]",
				Tags:     []string{"relay"},
				Domain:   socketDomain,
			}
		} else if len(directThreads) > 0 || detectLocalNode() != nil {
			socketThread = &protocol.ThreadMetadata{
				ID:       "socket",
				Hostname: "socket",
				RemoteIP: "none (direct mTLS)",
				Status:   "standalone [MODE: direct]",
				Tags:     []string{"relay", "direct"},
				Domain:   "fabric.mesh",
			}
		}
	}

	if socketErr != nil && len(threads) == 0 {
		if localNode := detectLocalNode(); localNode != nil {
			res := []protocol.ThreadMetadata{}
			if socketThread != nil {
				res = append(res, *socketThread)
			}
			res = append(res, *localNode)
			return res, nil
		}
		return nil, fmt.Errorf("%w\n  👉 Tip: If you are logged into a managed thread, inspect local daemon status with 'fabric thread service status'. To query the Fabric, run 'fabric ps' from your workstation or pass --server.", socketErr)
	}

	if socketThread != nil {
		threads = append([]protocol.ThreadMetadata{*socketThread}, threads...)
	}

	return threads, nil
}

// ListNodes is a backward-compatible alias for ListThreads.
func (c *Client) ListNodes() ([]protocol.ThreadMetadata, error) {
	return c.ListThreads()
}

func detectLocalNode() *protocol.ThreadMetadata {
	envCandidates := []string{
		"/etc/fabric/node.env",
	}
	if home, err := os.UserHomeDir(); err == nil {
		envCandidates = append(envCandidates,
			filepath.Join(home, ".config", "fabric", "node.env"),
			filepath.Join(home, ".fabric", "node.env"),
		)
	}

	for _, p := range envCandidates {
		envVars := parseEnvFile(p)
		if len(envVars) > 0 {
			listenAddr := envVars["FABRIC_LISTEN"]
			domain := envVars["FABRIC_DOMAIN"]
			if domain == "" {
				domain = "fabric.mesh"
			}
			tagsRaw := envVars["FABRIC_TAGS"]
			var tags []string
			if tagsRaw != "" {
				for _, t := range strings.Split(tagsRaw, ",") {
					if t = strings.TrimSpace(t); t != "" {
						tags = append(tags, t)
					}
				}
			}
			if listenAddr != "" {
				tags = append(tags, "remote")
			}

			hostname, _ := os.Hostname()
			if hostname == "" {
				hostname = "localhost"
			}

			status := "online [local daemon]"
			if listenAddr != "" {
				status = "online [MODE: remote (local)]"
			}

			ip := listenAddr
			if ip == "" {
				ip = "127.0.0.1"
			}

			return &protocol.ThreadMetadata{
				ID:          "local-" + hostname,
				Hostname:    hostname,
				RemoteIP:    ip,
				Status:      status,
				OS:          runtime.GOOS,
				Arch:        runtime.GOARCH,
				Tags:        tags,
				Domain:      domain,
				ConnectedAt: time.Now().UTC().Format(time.RFC3339),
			}
		}
	}
	return nil
}

// GetThread retrieves metadata for a single mesh thread from socket or local direct registry.
func (c *Client) GetThread(hostname string) (*protocol.ThreadMetadata, error) {
	if c.Config != nil {
		if entry, ok := c.Config.GetDirectThread(hostname); ok {
			displayHost := entry.Hostname
			if displayHost == "" {
				displayHost = hostname
			}
			domain := entry.Domain
			if domain == "" {
				domain = "fabric.mesh"
			}
			osName := entry.OS
			if osName == "" {
				osName = "linux"
			}

			return &protocol.ThreadMetadata{
				ID:          "direct-" + displayHost,
				Hostname:    displayHost,
				RemoteIP:    entry.Address,
				Status:      "online [MODE: remote]",
				OS:          osName,
				Arch:        entry.Arch,
				Tags:        entry.Tags,
				Domain:      domain,
				ConnectedAt: entry.RegisteredAt.Format(time.RFC3339),
			}, nil
		}
	}

	if localNode := detectLocalNode(); localNode != nil {
		if hostname == "self" || hostname == "local" || hostname == "localhost" ||
			hostname == localNode.Hostname || hostname == localNode.ID ||
			hostname == localNode.Hostname+"."+localNode.Domain {
			return localNode, nil
		}
	}

	// Try GET /threads/{hostname} first
	resp, err := c.DoHTTP("GET", "/threads/"+hostname, nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var meta protocol.ThreadMetadata
			if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
				return nil, err
			}
			return &meta, nil
		} else if resp.StatusCode != http.StatusNotFound {
			return nil, fmt.Errorf("failed to get thread %s: HTTP %s", hostname, resp.Status)
		}
	}

	// Fallback to GET /nodes/{hostname}
	respNode, errNode := c.DoHTTP("GET", "/nodes/"+hostname, nil)
	if errNode != nil {
		if err != nil {
			return nil, err
		}
		return nil, errNode
	}
	defer respNode.Body.Close()

	if respNode.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("thread '%s' not found", hostname)
	}
	if respNode.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get thread %s: HTTP %s", hostname, respNode.Status)
	}

	var meta protocol.ThreadMetadata
	if err := json.NewDecoder(respNode.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// GetNode is a backward-compatible alias for GetThread.
func (c *Client) GetNode(hostname string) (*protocol.ThreadMetadata, error) {
	return c.GetThread(hostname)
}


// Execute opens multiplexed stream(s) and executes a command across single nodes or parallel node fleets.
func (c *Client) Execute(opts ExecOptions, in io.Reader, out, errOut io.Writer) (*FleetResult, error) {
	if opts.All || opts.Tag != "" {
		return c.executeFleet(opts, out, errOut)
	}

	startTime := time.Now()
	err := c.executeSingle(opts, in, out, errOut)
	duration := time.Since(startTime).Round(time.Millisecond)

	res := ThreadExecResult{
		Thread:   opts.Target,
		Node:     opts.Target,
		Duration: duration,
	}

	if err != nil {
		res.Success = false
		res.Error = err
		var exitErr *ExitCodeError
		if errors.As(err, &exitErr) {
			res.ExitCode = strconv.Itoa(exitErr.Code)
		} else if strings.HasPrefix(err.Error(), "exit code ") {
			res.ExitCode = strings.TrimPrefix(err.Error(), "exit code ")
		} else {
			res.ExitCode = "ERR"
		}
		return &FleetThreadResult{
			Results:        []ThreadExecResult{res},
			Total:          1,
			SucceededCount: 0,
			FailedCount:    1,
			HasFailure:     true,
		}, err
	}

	res.Success = true
	res.ExitCode = "0"
	return &FleetThreadResult{
		Results:        []ThreadExecResult{res},
		Total:          1,
		SucceededCount: 1,
		FailedCount:    0,
		HasFailure:     false,
	}, nil
}

func (c *Client) executeFleet(opts ExecOptions, out, errOut io.Writer) (*FleetThreadResult, error) {
	allThreads, err := c.ListThreads()
	if err != nil {
		return nil, fmt.Errorf("failed to query active Fabric threads: %w", err)
	}

	var targets []protocol.ThreadMetadata
	for _, n := range allThreads {
		if n.ID == "socket" || strings.Contains(n.Status, "control-plane") || strings.HasPrefix(n.Status, "standalone") {
			continue
		}
		if opts.Tag != "" {
			for _, t := range n.Tags {
				if t == opts.Tag {
					targets = append(targets, n)
					break
				}
			}
		} else {
			targets = append(targets, n)
		}
	}
	if len(targets) == 0 {
		if opts.Tag != "" {
			return nil, fmt.Errorf("no active threads found with tag %q", opts.Tag)
		}
		return nil, fmt.Errorf("no active threads connected to Fabric")
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	sem := make(chan struct{}, concurrency)
	results := make([]ThreadExecResult, len(targets))
	var wg sync.WaitGroup
	var outMu sync.Mutex

	for i, node := range targets {
		wg.Add(1)
		go func(idx int, targetMeta protocol.ThreadMetadata) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			startTime := time.Now()
			stdoutWriter := NewLinePrefixedWriter(targetMeta.Hostname, out, &outMu)
			stderrWriter := NewLinePrefixedWriter(targetMeta.Hostname, errOut, &outMu)

			singleOpts := opts
			singleOpts.Target = targetMeta.Hostname
			singleOpts.All = false
			singleOpts.Tag = ""

			execErr := c.executeSingle(singleOpts, nil, stdoutWriter, stderrWriter)
			stdoutWriter.Flush()
			stderrWriter.Flush()

			duration := time.Since(startTime).Round(time.Millisecond)
			r := ThreadExecResult{
				Thread:   targetMeta.Hostname,
				Node:     targetMeta.Hostname,
				Duration: duration,
			}
			if execErr != nil {
				r.Success = false
				r.Error = execErr
				var exitErr *ExitCodeError
				if errors.As(execErr, &exitErr) {
					r.ExitCode = strconv.Itoa(exitErr.Code)
				} else if strings.HasPrefix(execErr.Error(), "exit code ") {
					r.ExitCode = strings.TrimPrefix(execErr.Error(), "exit code ")
				} else {
					r.ExitCode = "ERR"
				}
			} else {
				r.Success = true
				r.ExitCode = "0"
			}

			outMu.Lock()
			results[idx] = r
			outMu.Unlock()
		}(i, node)
	}

	wg.Wait()

	succeeded := 0
	failed := 0
	hasFailure := false
	for _, r := range results {
		if r.Success {
			succeeded++
		} else {
			failed++
			hasFailure = true
		}
	}

	if hasFailure {
		return &FleetThreadResult{
			Results:        results,
			Total:          len(results),
			SucceededCount: succeeded,
			FailedCount:    failed,
			HasFailure:     true,
		}, fmt.Errorf("fleet execution failed on 1 or more threads")
	}

	return &FleetThreadResult{
		Results:        results,
		Total:          len(results),
		SucceededCount: succeeded,
		FailedCount:    0,
		HasFailure:     false,
	}, nil
}

func (c *Client) executeSingle(opts ExecOptions, in io.Reader, out, errOut io.Writer) error {
	conn, err := c.DialWebSocketForNode(opts.Target)
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
			fd := int(file.Fd())
			oldState, err := term.MakeRaw(fd)
			if err == nil {
				var restoreOnce sync.Once
				restoreTerminal := func() {
					restoreOnce.Do(func() {
						_ = term.Restore(fd, oldState)
					})
				}
				defer restoreTerminal()

				// Trap OS termination signals to ensure terminal state is restored
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
				defer signal.Stop(sigCh)

				go func() {
					select {
					case <-sigCh:
						restoreTerminal()
					case <-mux.Session.CloseChan():
						restoreTerminal()
					}
				}()

				// Guarantee deferred terminal restoration upon panics
				defer func() {
					if r := recover(); r != nil {
						restoreTerminal()
						panic(r)
					}
				}()
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

	receivedExit := false
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
			receivedExit = true
			exitStr := string(frame.Payload)
			if exitStr != "0" {
				code, err := strconv.Atoi(exitStr)
				if err != nil {
					code = 1
				}
				return &ExitCodeError{Code: code}
			}
			return nil
		}
	}
	if !receivedExit {
		return fmt.Errorf("execution stream terminated unexpectedly")
	}
	return nil
}

// Upload streams a local file or directory as a Tar archive to a remote node destination.
func (c *Client) Upload(targetNode, localPath, remotePath string) (int64, error) {
	conn, err := c.DialWebSocketForNode(targetNode)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return 0, err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return 0, err
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

	stats, err := protocol.CreateTarWithStats(stream, localPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create upload archive: %w", err)
	}
	return stats.Bytes, nil
}

// Download streams a remote node path as a Tar archive and extracts it to a local destination.
func (c *Client) Download(targetNode, remotePath, localPath string) (int64, error) {
	conn, err := c.DialWebSocketForNode(targetNode)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return 0, err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return 0, err
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

	stats, err := protocol.ExtractTarWithStats(stream, localPath)
	if err != nil {
		return 0, fmt.Errorf("failed to extract download archive: %w", err)
	}
	return stats.Bytes, nil
}

// ForwardPort binds a local port and forwards incoming TCP connections to the remote node.
func (c *Client) ForwardPort(targetNode string, localPort, remotePort int) error {
	conn, err := c.DialWebSocketForNode(targetNode)
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
				TargetHost:     "127.0.0.1",
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
