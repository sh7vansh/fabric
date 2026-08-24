package provision

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"io"
	"net/http"

	"fabric/internal/protocol"
	"fabric/internal/service"
)

// StitchHostOptions defines parameters for provisioning a remote machine into the mesh.
type StitchHostOptions struct {
	Target       string
	SSHPort      string
	IdentityKey  string
	SocketURL    string
	Token        string
	Domain       string
	Tags         []string
	BinaryPath   string
	BinaryData   []byte
	CliBinaryData []byte
	NoWait       bool
	SilentOutput bool
}

// RemoteExecutor defines an interface for executing a bootstrap script on a remote host.
type RemoteExecutor interface {
	Run(script string) error
	QueryArch() (string, string, error)
}

// SSHExecutor implements RemoteExecutor using the local OpenSSH client.
type SSHExecutor struct {
	Target      string
	Port        string
	IdentityKey string
	Silent      bool
}

func (e *SSHExecutor) QueryArch() (string, string, error) {
	var sshArgs []string
	if e.Port != "" && e.Port != "22" {
		sshArgs = append(sshArgs, "-p", e.Port)
	}
	if e.IdentityKey != "" {
		sshArgs = append(sshArgs, "-i", e.IdentityKey)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", e.Target, "uname -s && uname -m")

	out, err := exec.Command("ssh", sshArgs...).Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) >= 2 {
		return strings.ToLower(strings.TrimSpace(lines[0])), strings.ToLower(strings.TrimSpace(lines[1])), nil
	}
	return "", "", fmt.Errorf("unexpected output from uname")
}

func (e *SSHExecutor) Run(script string) error {
	var sshArgs []string
	if e.Port != "" && e.Port != "22" {
		sshArgs = append(sshArgs, "-p", e.Port)
	}
	if e.IdentityKey != "" {
		sshArgs = append(sshArgs, "-i", e.IdentityKey)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", e.Target, "bash -s")

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = strings.NewReader(script)
	if !e.Silent {
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
	}

	return sshCmd.Run()
}

// FindLocalBinary locates the fabric-node binary on the local machine.
func FindLocalBinary(preferredPath string) (string, error) {
	if preferredPath != "" {
		if _, err := os.Stat(preferredPath); err == nil {
			return preferredPath, nil
		}
		return "", fmt.Errorf("specified binary path not found: %s", preferredPath)
	}

	// 1. Check directory of current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidate := filepath.Join(execDir, "fabric-node")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 2. Check system PATH
	if p, err := exec.LookPath("fabric-node"); err == nil {
		return p, nil
	}

	// 3. Check common bin locations
	candidates := []string{
		"./bin/fabric-node",
		"bin/fabric-node",
		"/usr/local/bin/fabric-node",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("fabric-node binary not found locally")
}

// FindLocalCliBinary locates the fabric cli binary on the local machine.
func FindLocalCliBinary() (string, error) {
	// 1. Check directory of current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidate := filepath.Join(execDir, "fabric")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 2. Check system PATH
	if p, err := exec.LookPath("fabric"); err == nil {
		return p, nil
	}

	// 3. Check common bin locations
	candidates := []string{
		"./bin/fabric",
		"bin/fabric",
		"/usr/local/bin/fabric",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("fabric cli binary not found locally")
}

// FetchReleaseBinary downloads a specific release binary from GitHub.
func FetchReleaseBinary(role, osName, arch string) ([]byte, error) {
	if osName != "linux" {
		return nil, fmt.Errorf("only linux is supported by pre-compiled binaries")
	}
	fabricArch := "amd64"
	switch arch {
	case "x86_64", "amd64":
		fabricArch = "amd64"
	case "aarch64", "arm64":
		fabricArch = "arm64"
	case "armv7l", "armhf", "arm":
		fabricArch = "arm"
	default:
		return nil, fmt.Errorf("unsupported arch: %s", arch)
	}

	binName := "fabric-linux-" + fabricArch
	if role == "node" {
		binName = "fabric-node-linux-" + fabricArch
	} else if role == "socket" {
		binName = "fabric-socket-linux-" + fabricArch
	}

	url := "https://github.com/sh7vansh/fabric/releases/latest/download/" + binName
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to download %s: HTTP %d", url, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ResolveCrossPlatformBinaries returns node and cli binaries matching the requested remote architecture.
func ResolveCrossPlatformBinaries(remoteOS, remoteArch string) (nodeBytes []byte, cliBytes []byte, err error) {
	// Normalize local arch mapping for comparison
	localArch := runtime.GOARCH
	remoteMappedArch := "amd64"
	switch remoteArch {
	case "aarch64", "arm64":
		remoteMappedArch = "arm64"
	case "armv7l", "armhf", "arm":
		remoteMappedArch = "arm"
	}

	// 1. If remote architecture matches local, use local binaries!
	if runtime.GOOS == remoteOS && localArch == remoteMappedArch {
		if p, err := FindLocalBinary(""); err == nil {
			nodeBytes, _ = os.ReadFile(p)
		}
		if p, err := FindLocalCliBinary(); err == nil {
			cliBytes, _ = os.ReadFile(p)
		}
		if len(nodeBytes) > 0 {
			return nodeBytes, cliBytes, nil
		}
	}

	// 2. Otherwise, fetch them directly from GitHub releases!
	fmt.Printf("[+] Remote architecture (%s/%s) differs from local. Downloading correct binaries from GitHub...\n", remoteOS, remoteMappedArch)
	
	nodeBytes, err = FetchReleaseBinary("node", remoteOS, remoteArch)
	if err != nil {
		return nil, nil, fmt.Errorf("cross-platform fetch failed for node: %w", err)
	}
	
	cliBytes, _ = FetchReleaseBinary("cli", remoteOS, remoteArch)
	
	return nodeBytes, cliBytes, nil
}

// PackageBinaryPayload compresses and base64-encodes binary data into an embedded payload string.
func PackageBinaryPayload(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// GenerateStitchScript generates the self-contained air-gapped bootstrap script for a remote host.
func GenerateStitchScript(opts StitchHostOptions, socketURL string) string {
	payload := ""
	if len(opts.BinaryData) > 0 {
		if p, err := PackageBinaryPayload(opts.BinaryData); err == nil {
			payload = p
		}
	} else {
		binPath, err := FindLocalBinary(opts.BinaryPath)
		if err == nil {
			if data, readErr := os.ReadFile(binPath); readErr == nil {
				if p, pkgErr := PackageBinaryPayload(data); pkgErr == nil {
					payload = p
				}
			}
		}
	}

	cliPayload := ""
	if len(opts.CliBinaryData) > 0 {
		if p, err := PackageBinaryPayload(opts.CliBinaryData); err == nil {
			cliPayload = p
		}
	} else {
		cliPath, err := FindLocalCliBinary()
		if err == nil {
			if data, readErr := os.ReadFile(cliPath); readErr == nil {
				if p, pkgErr := PackageBinaryPayload(data); pkgErr == nil {
					cliPayload = p
				}
			}
		}
	}

	mgr := service.NewInitManager()
	return mgr.RenderBootstrapScript(service.BootstrapScriptOptions{
		SocketURL:   socketURL,
		Token:       opts.Token,
		Domain:      opts.Domain,
		Tags:        opts.Tags,
		NodePayload: payload,
		CliPayload:  cliPayload,
	})
}

// KeyPromptFunc prompts the user to select an SSH key when authentication fails.
type KeyPromptFunc func(target string, availableKeys []string) (string, error)

// ProgressFunc reports status during batch or multi-stage operations.
type ProgressFunc func(current, total int, target, msg string)

// ProvisionResult stores the outcome of provisioning a target host into the mesh.
type ProvisionResult struct {
	Target   string
	Hostname string
	Success  bool
	Error    error
	Node     *protocol.NodeMetadata
}

// Provisioner provides an autonomous engine for provisioning remote nodes into the mesh.
type Provisioner struct {
	exec       RemoteExecutor
	verifier   NodeVerifierFunc
	keyPrompt  KeyPromptFunc
	onProgress ProgressFunc
}

// NewProvisioner creates a new Provisioner.
func NewProvisioner(exec RemoteExecutor, verifier NodeVerifierFunc) *Provisioner {
	return &Provisioner{
		exec:     exec,
		verifier: verifier,
	}
}

// WithKeyPrompt sets an interactive key prompt callback on SSH auth failure.
func (p *Provisioner) WithKeyPrompt(fn KeyPromptFunc) *Provisioner {
	p.keyPrompt = fn
	return p
}

// WithProgress sets a progress feedback callback for batch operations.
func (p *Provisioner) WithProgress(fn ProgressFunc) *Provisioner {
	p.onProgress = fn
	return p
}

// DiscoverLocalSSHKeys scans ~/.ssh for private keys.
func DiscoverLocalSSHKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	sshDir := filepath.Join(home, ".ssh")
	files, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}

	var keys []string
	for _, f := range files {
		if !f.IsDir() && !strings.HasSuffix(f.Name(), ".pub") &&
			!strings.HasPrefix(f.Name(), "known_hosts") &&
			!strings.HasPrefix(f.Name(), "config") &&
			!strings.HasPrefix(f.Name(), "authorized_keys") {
			keys = append(keys, filepath.Join(sshDir, f.Name()))
		}
	}
	return keys
}

// Provision stitches a single remote target host into the mesh with automatic key retry.
func (p *Provisioner) Provision(opts StitchHostOptions) (*protocol.NodeMetadata, error) {
	node, err := ExecuteStitchHost(opts, p.exec, p.verifier)
	if err != nil && strings.Contains(err.Error(), "exit status 255") && p.keyPrompt != nil {
		keys := DiscoverLocalSSHKeys()
		if len(keys) > 0 {
			chosenKey, promptErr := p.keyPrompt(opts.Target, keys)
			if promptErr == nil && chosenKey != "" {
				opts.IdentityKey = chosenKey
				return ExecuteStitchHost(opts, p.exec, p.verifier)
			}
		}
	}
	return node, err
}

// ProvisionBatch stitches multiple remote target hosts into the mesh concurrently.
func (p *Provisioner) ProvisionBatch(targets []StitchHostOptions) ([]ProvisionResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	results := make([]ProvisionResult, len(targets))
	concurrency := 8
	if len(targets) < concurrency {
		concurrency = len(targets)
	}

	type job struct {
		index int
		opts  StitchHostOptions
	}

	jobs := make(chan job, len(targets))
	for i, t := range targets {
		jobs <- job{index: i, opts: t}
	}
	close(jobs)

	var wg sync.WaitGroup
	var mu sync.Mutex
	completed := 0

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				mu.Lock()
				if p.onProgress != nil {
					p.onProgress(completed+1, len(targets), j.opts.Target, "stitching")
				}
				mu.Unlock()

				node, err := p.Provision(j.opts)
				res := ProvisionResult{
					Target: j.opts.Target,
					Node:   node,
				}
				if err != nil {
					res.Success = false
					res.Error = err
				} else {
					res.Success = true
					if node != nil {
						res.Hostname = node.Hostname
					} else {
						res.Hostname = j.opts.Target
					}
				}

				mu.Lock()
				completed++
				results[j.index] = res
				if p.onProgress != nil {
					if res.Success {
						p.onProgress(completed, len(targets), j.opts.Target, fmt.Sprintf("joined as %s", res.Hostname))
					} else {
						p.onProgress(completed, len(targets), j.opts.Target, fmt.Sprintf("failed: %v", err))
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return results, nil
}

// NodeVerifierFunc is a callback that queries the Socket for connected nodes.
type NodeVerifierFunc func(socketURL, token string) ([]protocol.NodeMetadata, error)

// ExecuteStitchHost performs the full bootstrap and mesh join verification workflow.
func ExecuteStitchHost(opts StitchHostOptions, exec RemoteExecutor, verifier NodeVerifierFunc) (*protocol.NodeMetadata, error) {
	socketURL := opts.SocketURL
	u, err := url.Parse(socketURL)
	if err == nil {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			outboundIP := GetOutboundIP()
			u.Host = net.JoinHostPort(outboundIP, port)
			socketURL = u.String()
			if !opts.SilentOutput {
				fmt.Printf("[+] Detected local loopback socket. Resolving remote socket URL to: %s\n", socketURL)
			}
		}
	}

	if !opts.SilentOutput {
		fmt.Printf("[+] Stitching target '%s' (port %s) into Fabric mesh...\n", opts.Target, opts.SSHPort)
		fmt.Printf("[+] Target Socket URL: %s\n", socketURL)
	}

	if exec == nil {
		exec = &SSHExecutor{
			Target:      opts.Target,
			Port:        opts.SSHPort,
			IdentityKey: opts.IdentityKey,
			Silent:      opts.SilentOutput,
		}
	}

	if len(opts.BinaryData) == 0 {
		osName, arch, err := exec.QueryArch()
		if err == nil {
			nodeBytes, cliBytes, resolveErr := ResolveCrossPlatformBinaries(osName, arch)
			if resolveErr == nil && len(nodeBytes) > 0 {
				opts.BinaryData = nodeBytes
				if len(cliBytes) > 0 {
					opts.CliBinaryData = cliBytes
				}
			} else {
				if !opts.SilentOutput {
					fmt.Printf("[!] Warning: Could not resolve cross-platform binaries (%v). Falling back to local binaries...\n", resolveErr)
				}
			}
		} else {
			if !opts.SilentOutput {
				fmt.Printf("[!] Warning: Could not query remote architecture (%v). Falling back to local binaries...\n", err)
			}
		}
	}

	bootstrapScript := GenerateStitchScript(opts, socketURL)

	if err := exec.Run(bootstrapScript); err != nil {
		return nil, fmt.Errorf("remote SSH bootstrap failed: %w", err)
	}

	if !opts.SilentOutput {
		fmt.Println("[+] Remote bootstrap executed successfully.")
	}

	if opts.NoWait || verifier == nil {
		return nil, nil
	}

	if !opts.SilentOutput {
		fmt.Print("[+] Waiting for node to establish WebSocket connection to Socket...")
	}

	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	targetHostOnly := opts.Target
	if atIdx := strings.LastIndex(opts.Target, "@"); atIdx != -1 {
		targetHostOnly = opts.Target[atIdx+1:]
	}

	for {
		select {
		case <-timeout:
			if !opts.SilentOutput {
				fmt.Println(" (timeout)")
				fmt.Println("[!] Warning: Node did not show up in the mesh within 15 seconds.")
				fmt.Println("    Check target logs via SSH: ssh " + opts.Target + " journalctl -u fabric-node -n 20")
			}
			return nil, fmt.Errorf("node connection verification timed out after 15s")
		case <-ticker.C:
			if !opts.SilentOutput {
				fmt.Print(".")
			}
			nodes, err := verifier(socketURL, opts.Token)
			if err != nil {
				continue
			}

			for _, n := range nodes {
				remoteHost := n.RemoteIP
				if h, _, err := net.SplitHostPort(n.RemoteIP); err == nil {
					remoteHost = h
				}
				if n.Hostname == targetHostOnly || remoteHost == targetHostOnly || targetHostOnly == "localhost" || targetHostOnly == "127.0.0.1" {
					if !opts.SilentOutput {
						fmt.Println(" Connected!")
					}
					return &n, nil
				}
			}
		}
	}
}

// GetOutboundIP determines preferred local outbound IPv4 address.
func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
