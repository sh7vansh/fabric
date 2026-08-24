package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
)

var (
	stitchIdentityFlag string
	stitchPortFlag     string
	stitchSocketURL    string
	stitchTokenFlag    string
	stitchDomainFlag   string
	stitchNoWait       bool

	// Discover flags
	discoverPortFlag        string
	discoverUserFlag        string
	discoverIdentityFlag    string
	discoverConcurrencyFlag int
	discoverTimeoutFlag     time.Duration
	discoverQuietFlag       bool
	discoverFormatFlag      string
	discoverAutoStitchFlag  bool
	discoverNoWaitFlag      bool
	discoverSocketURL       string
	discoverTokenFlag       string
	discoverDomainFlag      string
)

var stitchCmd = &cobra.Command{
	Use:   "stitch [flags] [user@]hostname[:port]",
	Short: "Bootstrap and stitch a remote host into the Fabric mesh over SSH",
	Args:  cobra.ExactArgs(1),
	RunE:  runStitch,
}

var stitchDiscoverCmd = &cobra.Command{
	Use:   "discover [flags] [CIDR]",
	Short: "Scan local or specified network for SSH endpoints and batch stitch into the mesh",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runStitchDiscover,
}

func init() {
	rootCmd.AddCommand(stitchCmd)
	stitchCmd.AddCommand(stitchDiscoverCmd)

	stitchCmd.Flags().StringVarP(&stitchIdentityFlag, "identity", "i", "", "SSH identity key file")
	stitchCmd.Flags().StringVarP(&stitchPortFlag, "port", "p", "22", "SSH port on target host")
	stitchCmd.Flags().StringVar(&stitchSocketURL, "socket-url", "", "Socket URL override (e.g. ws://192.168.1.50:8080/ws)")
	stitchCmd.Flags().StringVar(&stitchTokenFlag, "token", "", "Cluster token override")
	stitchCmd.Flags().StringVar(&stitchDomainFlag, "domain", "fabric.mesh", "Domain to register on the mesh")
	stitchCmd.Flags().BoolVar(&stitchNoWait, "no-wait", false, "Do not wait for mesh connection verification")

	// Discover command flags
	stitchDiscoverCmd.Flags().StringVarP(&discoverPortFlag, "port", "p", "22", "Port(s) to scan (comma-separated, e.g. 22,2222)")
	stitchDiscoverCmd.Flags().StringVarP(&discoverUserFlag, "user", "u", "", "Default SSH user for discovered hosts")
	stitchDiscoverCmd.Flags().StringVarP(&discoverIdentityFlag, "identity", "i", "", "SSH identity key file")
	stitchDiscoverCmd.Flags().IntVarP(&discoverConcurrencyFlag, "concurrency", "c", 128, "Concurrent probe workers")
	stitchDiscoverCmd.Flags().DurationVarP(&discoverTimeoutFlag, "timeout", "t", 1000*time.Millisecond, "Connection timeout per probe")
	stitchDiscoverCmd.Flags().BoolVarP(&discoverQuietFlag, "quiet", "q", false, "Only output discovered host endpoints")
	stitchDiscoverCmd.Flags().StringVar(&discoverFormatFlag, "format", "", "Output format ('json' or raw)")
	stitchDiscoverCmd.Flags().BoolVarP(&discoverAutoStitchFlag, "all", "a", false, "Automatically stitch all discovered hosts without prompt")
	stitchDiscoverCmd.Flags().BoolVar(&discoverAutoStitchFlag, "auto-stitch", false, "Alias for --all")
	stitchDiscoverCmd.Flags().BoolVar(&discoverNoWaitFlag, "no-wait", false, "Do not wait for mesh connection verification")
	stitchDiscoverCmd.Flags().StringVar(&discoverSocketURL, "socket-url", "", "Socket URL override")
	stitchDiscoverCmd.Flags().StringVar(&discoverTokenFlag, "token", "", "Cluster token override")
	stitchDiscoverCmd.Flags().StringVar(&discoverDomainFlag, "domain", "fabric.mesh", "Domain to register on the mesh")
}

type StitchHostOptions struct {
	Target       string
	SSHPort      string
	IdentityKey  string
	SocketURL    string
	Token        string
	Domain       string
	NoWait       bool
	SilentOutput bool
}

func runStitch(cmd *cobra.Command, args []string) error {
	rawTarget := args[0]
	cfg := GetConfig()

	sshPort := stitchPortFlag
	target := rawTarget
	if colonIdx := strings.LastIndex(rawTarget, ":"); colonIdx != -1 {
		portCandidate := rawTarget[colonIdx+1:]
		if !strings.Contains(portCandidate, "]") {
			target = rawTarget[:colonIdx]
			sshPort = portCandidate
		}
	}

	opts := StitchHostOptions{
		Target:      target,
		SSHPort:     sshPort,
		IdentityKey: stitchIdentityFlag,
		SocketURL:   stitchSocketURL,
		Token:       stitchTokenFlag,
		Domain:      stitchDomainFlag,
		NoWait:      stitchNoWait,
	}

	if opts.SocketURL == "" {
		opts.SocketURL = cfg.Host
	}
	if opts.Token == "" {
		opts.Token = cfg.Token
	}

	node, err := ExecuteStitchHost(opts)
	if err != nil {
		return err
	}

	if node != nil {
		fmt.Println("\n==================================================")
		fmt.Println("         Node Stitched Successfully!              ")
		fmt.Println("==================================================")
		fmt.Printf("Hostname:  %s\n", node.Hostname)
		fmt.Printf("Remote IP: %s\n", node.RemoteIP)
		fmt.Printf("OS/Arch:   %s/%s\n", node.OS, node.Arch)
		fmt.Printf("Status:    %s\n", node.Status)
		fmt.Println("\nTest remote execution with:")
		fmt.Printf("  fabric exec %s uname -a\n", node.Hostname)
		fmt.Println("==================================================")
	}

	return nil
}

func runStitchDiscover(cmd *cobra.Command, args []string) error {
	rawCIDR := ""
	if len(args) > 0 {
		rawCIDR = args[0]
	}

	targets, err := ParseTargets(rawCIDR)
	if err != nil {
		return fmt.Errorf("target resolution failed: %w", err)
	}

	var ports []int
	for _, pStr := range strings.Split(discoverPortFlag, ",") {
		pStr = strings.TrimSpace(pStr)
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		ports = []int{22}
	}

	scanOpts := ScanOptions{
		Ports:       ports,
		Concurrency: discoverConcurrencyFlag,
		Timeout:     discoverTimeoutFlag,
	}

	if !discoverQuietFlag && discoverFormatFlag != "json" {
		targetDesc := rawCIDR
		if targetDesc == "" {
			targetDesc = fmt.Sprintf("auto-detected subnet (%d hosts)", len(targets))
		}
		fmt.Printf("[+] Scanning %s for SSH endpoints (ports: %v, workers: %d)...\n", targetDesc, ports, scanOpts.Concurrency)
	}

	discovered, err := ScanTargets(targets, scanOpts, nil)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Quiet or JSON mode: output and exit
	if discoverQuietFlag || discoverFormatFlag == "json" {
		return FormatDiscoveredOutput(os.Stdout, discovered, discoverQuietFlag, discoverFormatFlag)
	}

	if len(discovered) == 0 {
		fmt.Println("[!] No SSH endpoints discovered.")
		return nil
	}

	fmt.Printf("\n[+] Discovered SSH Hosts (%d found):\n", len(discovered))
	PrintDiscoveryTable(os.Stdout, discovered)
	fmt.Println()

	var selectedTargets []StitchTarget

	if discoverAutoStitchFlag {
		fmt.Println("[+] --auto-stitch enabled. Stitching all discovered hosts...")
		for _, h := range discovered {
			selectedTargets = append(selectedTargets, StitchTarget{
				Host:   h.IP,
				Port:   strconv.Itoa(h.Port),
				User:   discoverUserFlag,
				Banner: h.CleanBanner,
			})
		}
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Select hosts to stitch [e.g. 1, admin@2, 3:2222, or 'all', 'q' to quit]: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		selectedTargets, err = ParseSelectionInput(input, discovered, discoverUserFlag)
		if err != nil {
			return fmt.Errorf("selection error: %w", err)
		}

		if len(selectedTargets) == 0 {
			fmt.Println("[*] No hosts selected. Exiting.")
			return nil
		}
	}

	cfg := GetConfig()
	socketURL := discoverSocketURL
	if socketURL == "" {
		socketURL = cfg.Host
	}
	token := discoverTokenFlag
	if token == "" {
		token = cfg.Token
	}

	fmt.Printf("\n[+] Starting batch stitch of %d selected host(s)...\n\n", len(selectedTargets))

	type stitchResult struct {
		Target   string
		Hostname string
		Success  bool
		Error    string
	}

	var results []stitchResult

	for i, st := range selectedTargets {
		fmt.Printf("--------------------------------------------------\n")
		fmt.Printf("[*] [%d/%d] Stitching %s...\n", i+1, len(selectedTargets), st.TargetSpec())
		fmt.Printf("--------------------------------------------------\n")

		opts := StitchHostOptions{
			Target:      st.Host,
			SSHPort:     st.Port,
			IdentityKey: discoverIdentityFlag,
			SocketURL:   socketURL,
			Token:       token,
			Domain:      discoverDomainFlag,
			NoWait:      discoverNoWaitFlag,
		}
		if st.User != "" {
			opts.Target = st.User + "@" + st.Host
		}

		node, err := ExecuteStitchHost(opts)
		if err != nil {
			fmt.Printf("[✗] Failed to stitch %s: %v\n\n", st.TargetSpec(), err)
			results = append(results, stitchResult{
				Target:  st.TargetSpec(),
				Success: false,
				Error:   err.Error(),
			})
		} else {
			hostname := st.Host
			if node != nil {
				hostname = node.Hostname
			}
			fmt.Printf("[✓] %s successfully stitched as '%s'!\n\n", st.TargetSpec(), hostname)
			results = append(results, stitchResult{
				Target:   st.TargetSpec(),
				Hostname: hostname,
				Success:  true,
			})
		}
	}

	// Print final Batch Summary Table
	fmt.Println("\n==================================================")
	fmt.Println("             Batch Stitch Summary                 ")
	fmt.Println("==================================================")
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
			fmt.Printf(" [✓] %-25s -> %s (Online)\n", r.Target, r.Hostname)
		} else {
			fmt.Printf(" [✗] %-25s -> Failed: %s\n", r.Target, r.Error)
		}
	}
	fmt.Println("==================================================")
	fmt.Printf("Total: %d | Joined: %d | Failed: %d\n\n", len(results), successCount, len(results)-successCount)

	return nil
}

func ExecuteStitchHost(opts StitchHostOptions) (*protocol.NodeMetadata, error) {
	socketURL := opts.SocketURL
	u, err := url.Parse(socketURL)
	if err == nil {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			outboundIP := getOutboundIP()
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

	bootstrapScript := fmt.Sprintf(`#!/usr/bin/env bash
set -e

echo "[+] Initializing Fabric node setup on remote host..."

SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

$SUDO mkdir -p /etc/fabric /usr/local/bin

cat << 'EOF' | $SUDO tee /etc/fabric/node.env > /dev/null
FABRIC_SOCKET_URL=%s
FABRIC_TOKEN=%s
FABRIC_DOMAIN=%s
EOF

$SUDO chmod 600 /etc/fabric/node.env

if command -v fabric >/dev/null 2>&1; then
    echo "[+] Fabric CLI found on target."
    $SUDO fabric service install node || true
elif [ -f /usr/local/bin/fabric ]; then
    $SUDO /usr/local/bin/fabric service install node || true
else
    echo "[+] Installing Fabric binaries on remote..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://get.fabric.mesh/install.sh 2>/dev/null | FABRIC_NO_SETUP=1 bash || true
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl daemon-reload || true
    $SUDO systemctl restart fabric-node || true
    $SUDO systemctl enable fabric-node || true
    echo "[+] fabric-node systemd service enabled and started."
fi
`, socketURL, opts.Token, opts.Domain)

	var sshArgs []string
	if opts.SSHPort != "" && opts.SSHPort != "22" {
		sshArgs = append(sshArgs, "-p", opts.SSHPort)
	}
	if opts.IdentityKey != "" {
		sshArgs = append(sshArgs, "-i", opts.IdentityKey)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", opts.Target, "bash -s")

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = strings.NewReader(bootstrapScript)
	if !opts.SilentOutput {
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
	}

	if err := sshCmd.Run(); err != nil {
		return nil, fmt.Errorf("remote SSH bootstrap failed: %w", err)
	}

	if !opts.SilentOutput {
		fmt.Println("[+] Remote bootstrap executed successfully.")
	}

	if opts.NoWait {
		return nil, nil
	}

	if !opts.SilentOutput {
		fmt.Print("[+] Waiting for node to establish WebSocket connection to Socket...")
	}

	client := NewClient(&Config{Host: socketURL, Token: opts.Token})
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
			resp, err := client.DoHTTP("GET", "/nodes", nil)
			if err != nil {
				continue
			}

			var nodes []protocol.NodeMetadata
			if err := json.NewDecoder(resp.Body).Decode(&nodes); err == nil {
				resp.Body.Close()
				for _, n := range nodes {
					if n.Hostname == targetHostOnly || strings.HasPrefix(n.RemoteIP, targetHostOnly) || targetHostOnly == "localhost" || targetHostOnly == "127.0.0.1" {
						if !opts.SilentOutput {
							fmt.Println(" Connected!")
						}
						return &n, nil
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
