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

	"fabric/internal/pki"
	"fabric/internal/protocol"
	"fabric/internal/service"
)

// StitchHostOptions defines parameters for provisioning a remote machine into the mesh.
type StitchHostOptions struct {
	Target        string
	SSHPort       string
	IdentityKey   string
	SocketURL     string
	Token         string
	Domain        string
	Tags          []string
	BinaryPath    string
	BinaryData    []byte
	CliBinaryData []byte
	NoWait        bool
	SilentOutput  bool
	Mode          string        // "normal" or "inverted"
	ListenPort    string        // default "8443"
	NoFallback    bool          // disable auto-fallback from normal to inverted
	VerifyTimeout time.Duration // timeout for socket connection verification (default 15s)
	CADir         string        // optional CA directory
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

func (e *SSHExecutor) QuerySystemInfo() (string, string, string, error) {
	var sshArgs []string
	if e.Port != "" && e.Port != "22" {
		sshArgs = append(sshArgs, "-p", e.Port)
	}
	if e.IdentityKey != "" {
		sshArgs = append(sshArgs, "-i", e.IdentityKey)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", "--", e.Target, "uname -s && uname -m && hostname")

	out, err := exec.Command("ssh", sshArgs...).Output()
	if err != nil {
		return "", "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	osName := ""
	arch := ""
	hostname := ""
	if len(lines) >= 1 {
		osName = strings.ToLower(strings.TrimSpace(lines[0]))
	}
	if len(lines) >= 2 {
		arch = strings.ToLower(strings.TrimSpace(lines[1]))
	}
	if len(lines) >= 3 {
		hostname = strings.TrimSpace(lines[2])
	}
	if osName != "" && arch != "" {
		return osName, arch, hostname, nil
	}
	return "", "", "", fmt.Errorf("unexpected output from uname/hostname")
}

func (e *SSHExecutor) QueryArch() (string, string, error) {
	osName, arch, _, err := e.QuerySystemInfo()
	return osName, arch, err
}

func (e *SSHExecutor) Run(script string) error {
	var sshArgs []string
	if e.Port != "" && e.Port != "22" {
		sshArgs = append(sshArgs, "-p", e.Port)
	}
	if e.IdentityKey != "" {
		sshArgs = append(sshArgs, "-i", e.IdentityKey)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", "--", e.Target, "bash -s")

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = strings.NewReader(script)
	if !e.Silent {
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
	}

	return sshCmd.Run()
}

// FindLocalBinary locates the fabric-thread (or fallback fabric-node) binary on the local machine.
func FindLocalBinary(preferredPath string) (string, error) {
	if preferredPath != "" {
		if _, err := os.Stat(preferredPath); err == nil {
			return preferredPath, nil
		}
		return "", fmt.Errorf("specified binary path not found: %s", preferredPath)
	}

	binNames := []string{"fabric-thread", "fabric-node"}

	// 1. Check directory of current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		for _, name := range binNames {
			candidate := filepath.Join(execDir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}

	// 2. Check system PATH
	for _, name := range binNames {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}

	// 3. Check common bin locations
	for _, name := range binNames {
		candidates := []string{
			"./bin/" + name,
			"bin/" + name,
			"/usr/local/bin/" + name,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
		}
	}

	return "", fmt.Errorf("fabric-thread binary not found locally")
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

	domain := opts.Domain
	if domain == "" {
		domain = "fabric.mesh"
	}

	// Locate and load CA to mint leaf certificate
	caDir := opts.CADir
	if caDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cand := filepath.Join(home, ".fabric", "ca")
			if _, err := os.Stat(filepath.Join(cand, "ca.crt")); err == nil {
				caDir = cand
			} else if _, err := os.Stat(filepath.Join(home, ".fabric", "ca.crt")); err == nil {
				caDir = filepath.Join(home, ".fabric")
			}
		}
		if caDir == "" {
			if _, err := os.Stat("/etc/fabric/ca.crt"); err == nil {
				caDir = "/etc/fabric"
			}
		}
		if caDir == "" {
			if home, err := os.UserHomeDir(); err == nil {
				caDir = filepath.Join(home, ".fabric", "ca")
			} else {
				caDir = "/etc/fabric"
			}
		}
	}

	targetHostOnly := opts.Target
	if atIdx := strings.LastIndex(opts.Target, "@"); atIdx != -1 {
		targetHostOnly = opts.Target[atIdx+1:]
	}
	if colonIdx := strings.LastIndex(targetHostOnly, ":"); colonIdx != -1 {
		targetHostOnly = targetHostOnly[:colonIdx]
	}

	caPayload := ""
	certPayload := ""
	keyPayload := ""

	if ca, err := pki.LoadOrInitCA(caDir, domain); err == nil && ca != nil {
		hosts := []string{targetHostOnly}
		if net.ParseIP(targetHostOnly) == nil && !strings.Contains(targetHostOnly, ".") && domain != "" {
			hosts = append(hosts, targetHostOnly+"."+domain)
		}
		if domain != "" {
			hosts = append(hosts, "*."+domain)
		}
		if certPEM, keyPEM, err := ca.MintCertificatePEM(hosts, 90*24*time.Hour); err == nil {
			caPayload = base64.StdEncoding.EncodeToString(ca.CertPEM())
			certPayload = base64.StdEncoding.EncodeToString(certPEM)
			keyPayload = base64.StdEncoding.EncodeToString(keyPEM)
		}
	}

	listenAddr := ""
	if opts.Mode == "inverted" || opts.Mode == "remote" {
		port := opts.ListenPort
		if port == "" {
			port = "8443"
		}
		if !strings.HasPrefix(port, ":") {
			port = ":" + port
		}
		listenAddr = port
	}

	mgr := service.NewInitManager()
	return mgr.RenderBootstrapScript(service.BootstrapScriptOptions{
		SocketURL:   socketURL,
		ListenAddr:  listenAddr,
		Token:       opts.Token,
		Domain:      opts.Domain,
		Tags:        opts.Tags,
		NodePayload: payload,
		CliPayload:  cliPayload,
		CAPayload:   caPayload,
		CertPayload: certPayload,
		KeyPayload:  keyPayload,
	})
}

// KeyPromptFunc prompts the user to select an SSH key when authentication fails.
type KeyPromptFunc func(target string, availableKeys []string) (string, error)

// ProgressFunc reports status during batch or multi-stage operations.
type ProgressFunc func(current, total int, target, msg string)

// DirectProberFunc is a callback that verifies direct mTLS connectivity to an inverted node.
type DirectProberFunc func(targetAddr, caPath string, timeout time.Duration) error

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
	prober     DirectProberFunc
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

// WithDirectProber sets a custom direct probe callback for inverted node verification.
func (p *Provisioner) WithDirectProber(fn DirectProberFunc) *Provisioner {
	p.prober = fn
	return p
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
	node, err := ExecuteStitchHost(opts, p.exec, p.verifier, p.prober)
	if err != nil && strings.Contains(err.Error(), "exit status 255") && p.keyPrompt != nil {
		keys := DiscoverLocalSSHKeys()
		if len(keys) > 0 {
			chosenKey, promptErr := p.keyPrompt(opts.Target, keys)
			if promptErr == nil && chosenKey != "" {
				opts.IdentityKey = chosenKey
				return ExecuteStitchHost(opts, p.exec, p.verifier, p.prober)
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
func ExecuteStitchHost(opts StitchHostOptions, exec RemoteExecutor, verifier NodeVerifierFunc, prober ...DirectProberFunc) (*protocol.NodeMetadata, error) {
	socketURL := opts.SocketURL
	if opts.Mode != "inverted" && opts.Mode != "remote" {
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
	} else {
		socketURL = ""
	}

	listenPort := opts.ListenPort
	if listenPort == "" {
		listenPort = "8443"
	}
	opts.ListenPort = listenPort

	targetHostOnly := opts.Target
	if atIdx := strings.LastIndex(opts.Target, "@"); atIdx != -1 {
		targetHostOnly = opts.Target[atIdx+1:]
	}
	if colonIdx := strings.LastIndex(targetHostOnly, ":"); colonIdx != -1 {
		targetHostOnly = targetHostOnly[:colonIdx]
	}

	if !opts.SilentOutput {
		modeStr := "Normal"
		if opts.Mode == "inverted" || opts.Mode == "remote" {
			modeStr = fmt.Sprintf("Remote (:%s)", listenPort)
		}
		fmt.Printf("[+] Stitching target '%s' (port %s, mode: %s) into Fabric mesh...\n", opts.Target, opts.SSHPort, modeStr)
		if opts.Mode != "inverted" && opts.Mode != "remote" {
			fmt.Printf("[+] Target Socket URL: %s\n", socketURL)
		}
	}

	if exec == nil {
		exec = &SSHExecutor{
			Target:      opts.Target,
			Port:        opts.SSHPort,
			IdentityKey: opts.IdentityKey,
			Silent:      opts.SilentOutput,
		}
	}

	remoteOS := "linux"
	remoteArch := "amd64"
	remoteHostname := ""

	if sysExec, ok := exec.(interface{ QuerySystemInfo() (string, string, string, error) }); ok {
		osName, arch, hname, err := sysExec.QuerySystemInfo()
		if err == nil {
			remoteOS = osName
			remoteArch = arch
			remoteHostname = hname
		}
	} else if exec != nil {
		osName, arch, err := exec.QueryArch()
		if err == nil {
			remoteOS = osName
			remoteArch = arch
		}
	}

	if len(opts.BinaryData) == 0 {
		nodeBytes, cliBytes, resolveErr := ResolveCrossPlatformBinaries(remoteOS, remoteArch)
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
	}

	bootstrapScript := GenerateStitchScript(opts, socketURL)

	if err := exec.Run(bootstrapScript); err != nil {
		return nil, fmt.Errorf("remote SSH bootstrap failed: %w", err)
	}

	if !opts.SilentOutput {
		fmt.Println("[+] Remote bootstrap executed successfully.")
	}

	if opts.NoWait {
		return nil, nil
	}

	var proberFn DirectProberFunc = pki.ProbeDirectMTLS
	if len(prober) > 0 && prober[0] != nil {
		proberFn = prober[0]
	}

	targetProbeAddr := net.JoinHostPort(targetHostOnly, listenPort)
	caCertPath := ""
	if opts.CADir != "" {
		caCertPath = filepath.Join(opts.CADir, "ca.crt")
	} else if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, ".fabric", "ca", "ca.crt")
		if _, err := os.Stat(cand); err == nil {
			caCertPath = cand
		} else if _, err := os.Stat(filepath.Join(home, ".fabric", "ca.crt")); err == nil {
			caCertPath = filepath.Join(home, ".fabric", "ca.crt")
		}
	}

	// 1. Explicit Remote / Inverted Mode Verification
	if opts.Mode == "inverted" || opts.Mode == "remote" {
		if !opts.SilentOutput {
			fmt.Printf("[+] Verifying remote thread listener via direct mTLS probe (%s)...", targetProbeAddr)
		}
		return verifyDirectInvertedProbe(proberFn, targetProbeAddr, caCertPath, targetHostOnly, listenPort, remoteHostname, remoteOS, remoteArch, opts, false)
	}

	// 2. Normal Mode Verification with Automatic Fallback State Machine
	if verifier == nil {
		return nil, nil
	}

	if !opts.SilentOutput {
		fmt.Print("[+] Waiting for thread to establish WebSocket connection to Server...")
	}

	verifyTimeout := opts.VerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = 15 * time.Second
	}
	timeout := time.After(verifyTimeout)
	tickerInterval := 1 * time.Second
	if verifyTimeout < 1*time.Second {
		tickerInterval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			if opts.NoFallback {
				if !opts.SilentOutput {
					fmt.Println(" (timeout)")
					fmt.Println("[!] Warning: Thread did not show up in the Fabric within 15 seconds.")
					fmt.Println("    Check target logs via SSH: ssh " + opts.Target + " journalctl -u fabric-thread -n 20")
				}
				return nil, fmt.Errorf("thread connection verification timed out after %v", verifyTimeout)
			}

			// Automatic Fallback Trigger
			if !opts.SilentOutput {
				fmt.Println(" (timeout)")
				fmt.Println("[!] Normal connection verification timed out (server unreachable).")
				fmt.Printf("[+] Automatically switching remote thread to Remote Mode (:%s)...\n", listenPort)
			}

			mgr := service.NewInitManager()
			switchScript := mgr.RenderInvertedSwitchScript(listenPort)
			if err := exec.Run(switchScript); err != nil {
				return nil, fmt.Errorf("failed to switch thread to remote mode: %w", err)
			}

			if !opts.SilentOutput {
				fmt.Printf("[+] Probing remote thread via direct mTLS (%s)...", targetProbeAddr)
			}

			return verifyDirectInvertedProbe(proberFn, targetProbeAddr, caCertPath, targetHostOnly, listenPort, remoteHostname, remoteOS, remoteArch, opts, true)

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

func verifyDirectInvertedProbe(proberFn DirectProberFunc, targetProbeAddr, caCertPath, targetHostOnly, listenPort, remoteHostname, remoteOS, remoteArch string, opts StitchHostOptions, isFallback bool) (*protocol.NodeMetadata, error) {
	prefix := "Direct"
	if isFallback {
		prefix = "Fallback direct"
	}
	if err := proberFn(targetProbeAddr, caCertPath, 5*time.Second); err != nil {
		if !opts.SilentOutput {
			fmt.Println(" (failed)")
			fmt.Printf("\n[!] %s mTLS probe failed to connect to %s: %v\n", prefix, targetProbeAddr, err)
			fmt.Println("\nTroubleshooting Suggestions:")
			fmt.Printf("  1. Verify incoming TCP port %s is open: ssh %s 'sudo ufw allow %s/tcp'\n", listenPort, opts.Target, listenPort)
			fmt.Printf("  2. Check thread service logs: ssh %s journalctl -u fabric-thread -n 30 --no-pager\n", opts.Target)
			fmt.Printf("  3. Verify port is listening: ssh %s 'ss -tulpn | grep %s'\n\n", opts.Target, listenPort)
		}
		return nil, fmt.Errorf("%s remote direct mTLS probe failed: %w", strings.ToLower(prefix), err)
	}

	if !opts.SilentOutput {
		fmt.Println(" Connected!")
		if isFallback {
			fmt.Printf("[+] Remote thread switched to Remote Mode successfully (listening on :%s)!\n", listenPort)
		} else {
			fmt.Printf("[+] Direct mTLS connection to :%s verified successfully.\n", listenPort)
		}
	}

	displayHostname := remoteHostname
	if displayHostname == "" {
		displayHostname = targetHostOnly
	}
	domain := opts.Domain
	if domain == "" {
		domain = "fabric.mesh"
	}

	return &protocol.NodeMetadata{
		ID:          "direct-" + displayHostname,
		Hostname:    displayHostname,
		RemoteIP:    targetProbeAddr,
		OS:          remoteOS,
		Arch:        remoteArch,
		Status:      "online [MODE: remote]",
		Tags:        append(opts.Tags, "remote"),
		Domain:      domain,
		ConnectedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
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
