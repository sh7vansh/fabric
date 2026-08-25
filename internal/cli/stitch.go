package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"fabric/internal/protocol"
	"fabric/internal/provision"

	"github.com/spf13/cobra"
)

var (
	stitchServerURL      string
	stitchSocketURL      string
	stitchIdentityFlag   string
	stitchPortFlag       string
	stitchUserFlag       string
	stitchTokenFlag      string
	stitchDomainFlag     string
	stitchTagsFlag       string
	stitchNoWait         bool
	stitchModeFlag       string
	stitchRemoteFlag     bool
	stitchInvertedFlag   bool
	stitchListenPortFlag string
	stitchNoFallback     bool

	// Discovery / batch flags
	stitchConcurrencyFlag int
	stitchTimeoutFlag     time.Duration
	stitchQuietFlag       bool
	stitchFormatFlag      string
	stitchBatchFlag       bool
)

var stitchCmd = &cobra.Command{
	Use:          "stitch [flags] [TARGET | CIDR]",
	Short:        "Bootstrap host over SSH or scan subnet into Fabric",
	GroupID:      "network",
	SilenceUsage: true,
	Long: `Automate provisioning of remote machines into the Fabric over SSH or scan a subnet.

Passing a single target (e.g. user@192.168.1.50) connects via SSH, installs the Fabric agent,
and joins the machine as a thread. Passing a CIDR (e.g. 192.168.1.0/24) scans the subnet
for SSH hosts and prompts for interactive or batch onboarding.`,
	Example: `  # Stitch a single remote machine as a thread
  fabric stitch root@192.168.1.50

  # Scan subnet and interactively select machines to stitch
  fabric stitch 192.168.1.0/24

  # Scan and auto-stitch all discovered subnet hosts
  fabric stitch --batch --user ubuntu 10.0.0.0/24

  # Auto-detect local subnet and discover machines
  fabric stitch

  # Stitch with direct remote mTLS listening mode
  fabric stitch --remote --listen-port 8443 ubuntu@10.0.0.12`,
	Args: cobra.MaximumNArgs(1),
	RunE: runStitch,
}

var stitchDiscoverCmd = &cobra.Command{
	Use:          "discover [flags] [CIDR]",
	Short:        "Scan local or specified network for SSH endpoints (deprecated, use 'fabric stitch [CIDR]')",
	SilenceUsage: true,
	Args:         cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rawCIDR := ""
		if len(args) > 0 {
			rawCIDR = args[0]
			WarnDeprecated("fabric stitch discover "+rawCIDR, "fabric stitch "+rawCIDR)
		} else {
			WarnDeprecated("fabric stitch discover", "fabric stitch")
		}
		return runStitchScan(cmd, rawCIDR)
	},
}

func init() {
	rootCmd.AddCommand(stitchCmd)
	stitchCmd.AddCommand(stitchDiscoverCmd)

	stitchCmd.Flags().StringVarP(&stitchIdentityFlag, "identity", "i", "", "SSH identity key file")
	stitchCmd.Flags().StringVarP(&stitchPortFlag, "port", "p", "22", "SSH port on target host (or ports to scan, e.g. 22,2222)")
	stitchCmd.Flags().StringVarP(&stitchUserFlag, "user", "u", "", "Default SSH user for discovered hosts")
	stitchCmd.Flags().StringVarP(&stitchServerURL, "server", "s", "", "Fabric server URL override")
	stitchCmd.Flags().StringVar(&stitchSocketURL, "socket-url", "", "Server URL override (deprecated, use --server)")
	stitchCmd.Flags().StringVar(&stitchTokenFlag, "token", "", "Cluster token override")
	stitchCmd.Flags().StringVar(&stitchDomainFlag, "domain", "fabric.mesh", "Domain to register on the Fabric")
	stitchCmd.Flags().StringVar(&stitchTagsFlag, "tags", "", "Comma-separated metadata tags (e.g. web,prod)")
	stitchCmd.Flags().BoolVar(&stitchNoWait, "no-wait", false, "Do not wait for mesh connection verification")
	stitchCmd.Flags().StringVar(&stitchModeFlag, "mode", "", "Connection mode topology: 'local' or 'remote'")
	stitchCmd.Flags().BoolVar(&stitchRemoteFlag, "remote", false, "Direct remote mode (thread listens with mTLS)")
	stitchCmd.Flags().BoolVar(&stitchInvertedFlag, "inverted", false, "Alias for --remote (deprecated, use --remote)")
	stitchCmd.Flags().StringVar(&stitchListenPortFlag, "listen-port", "8443", "Port for remote mode thread to listen on")
	stitchCmd.Flags().BoolVar(&stitchNoFallback, "no-fallback", false, "Disable automatic fallback to remote mode if normal verification times out")

	// Discovery flags on stitchCmd
	stitchCmd.Flags().IntVarP(&stitchConcurrencyFlag, "concurrency", "c", 128, "Concurrent probe workers")
	stitchCmd.Flags().DurationVarP(&stitchTimeoutFlag, "timeout", "t", 1000*time.Millisecond, "Connection timeout per probe")
	stitchCmd.Flags().BoolVarP(&stitchQuietFlag, "quiet", "q", false, "Only output discovered host endpoints")
	stitchCmd.Flags().StringVar(&stitchFormatFlag, "format", "", "Output format ('json' or raw)")
	stitchCmd.Flags().BoolVarP(&stitchBatchFlag, "all", "a", false, "Automatically stitch all discovered hosts without prompt")
	stitchCmd.Flags().BoolVar(&stitchBatchFlag, "batch", false, "Alias for --all")
	stitchCmd.Flags().BoolVar(&stitchBatchFlag, "auto-stitch", false, "Alias for --all")

	// Discover command flags for backward compatibility
	stitchDiscoverCmd.Flags().StringVarP(&stitchPortFlag, "port", "p", "22", "Port(s) to scan (comma-separated, e.g. 22,2222)")
	stitchDiscoverCmd.Flags().StringVarP(&stitchUserFlag, "user", "u", "", "Default SSH user for discovered hosts")
	stitchDiscoverCmd.Flags().StringVarP(&stitchIdentityFlag, "identity", "i", "", "SSH identity key file")
	stitchDiscoverCmd.Flags().IntVarP(&stitchConcurrencyFlag, "concurrency", "c", 128, "Concurrent probe workers")
	stitchDiscoverCmd.Flags().DurationVarP(&stitchTimeoutFlag, "timeout", "t", 1000*time.Millisecond, "Connection timeout per probe")
	stitchDiscoverCmd.Flags().BoolVarP(&stitchQuietFlag, "quiet", "q", false, "Only output discovered host endpoints")
	stitchDiscoverCmd.Flags().StringVar(&stitchFormatFlag, "format", "", "Output format ('json' or raw)")
	stitchDiscoverCmd.Flags().BoolVarP(&stitchBatchFlag, "all", "a", false, "Automatically stitch all discovered hosts without prompt")
	stitchDiscoverCmd.Flags().BoolVar(&stitchBatchFlag, "batch", false, "Alias for --all")
	stitchDiscoverCmd.Flags().BoolVar(&stitchBatchFlag, "auto-stitch", false, "Alias for --all")
	stitchDiscoverCmd.Flags().BoolVar(&stitchNoWait, "no-wait", false, "Do not wait for mesh connection verification")
	stitchDiscoverCmd.Flags().StringVarP(&stitchServerURL, "server", "s", "", "Fabric server URL override")
	stitchDiscoverCmd.Flags().StringVar(&stitchSocketURL, "socket-url", "", "Server URL override (deprecated, use --server)")
	stitchDiscoverCmd.Flags().StringVar(&stitchTokenFlag, "token", "", "Cluster token override")
	stitchDiscoverCmd.Flags().StringVar(&stitchDomainFlag, "domain", "fabric.mesh", "Domain to register on the mesh")
	stitchDiscoverCmd.Flags().StringVar(&stitchTagsFlag, "tags", "", "Comma-separated metadata tags to assign to discovered threads")
	stitchDiscoverCmd.Flags().StringVar(&stitchModeFlag, "mode", "", "Connection mode topology: 'local' or 'remote'")
	stitchDiscoverCmd.Flags().BoolVar(&stitchRemoteFlag, "remote", false, "Direct remote mode")
	stitchDiscoverCmd.Flags().BoolVar(&stitchInvertedFlag, "inverted", false, "Alias for --remote (deprecated, use --remote)")
	stitchDiscoverCmd.Flags().StringVar(&stitchListenPortFlag, "listen-port", "8443", "Port for remote mode threads to listen on")
	stitchDiscoverCmd.Flags().BoolVar(&stitchNoFallback, "no-fallback", false, "Disable automatic fallback to remote mode")
}

func nodeVerifier(socketURL, token string) ([]protocol.NodeMetadata, error) {
	client := NewClient(&Config{Host: socketURL, Token: token})
	return client.ListNodes()
}

func parseTags(raw string) []string {
	if raw == "" {
		return nil
	}
	var tags []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func isTerminalInput() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func promptTopology(isBatch bool) string {
	if isBatch {
		fmt.Println("\nSelect connection topology for discovered hosts:")
	} else {
		fmt.Println("\nSelect connection topology:")
	}
	fmt.Println("  [1] Local (Outbound WebSocket to Fabric server — default)")
	fmt.Println("  [2] Remote (Thread listens with mTLS for direct CLI access)")
	fmt.Print("Choice [1]: ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "2" || input == "remote" || input == "inverted" {
		return "inverted"
	}
	return "normal"
}

func resolveStitchMode(modeFlag string, remoteFlag, invertedFlag bool) (string, error) {
	if invertedFlag {
		WarnDeprecated("--inverted", "--remote")
	}
	mode := strings.ToLower(strings.TrimSpace(modeFlag))
	if remoteFlag || invertedFlag {
		mode = "remote"
	}
	if mode != "" && mode != "local" && mode != "remote" && mode != "normal" && mode != "inverted" {
		return "", fmt.Errorf("invalid mode %q: must be 'local' or 'remote'", modeFlag)
	}
	if mode == "remote" || mode == "inverted" {
		return "inverted", nil
	}
	if mode == "local" || mode == "normal" {
		return "normal", nil
	}
	return "", nil
}

func registerInvertedIfApplicable(target, listenPort string, node *protocol.NodeMetadata) {
	if node == nil {
		return
	}
	isInverted := strings.Contains(node.Status, "inverted") || strings.Contains(node.Status, "remote")
	for _, t := range node.Tags {
		if t == "inverted" || t == "remote" {
			isInverted = true
			break
		}
	}
	if isInverted {
		targetHostOnly := target
		if atIdx := strings.LastIndex(target, "@"); atIdx != -1 {
			targetHostOnly = target[atIdx+1:]
		}
		directAddr := net.JoinHostPort(targetHostOnly, listenPort)
		domain := node.Domain
		if domain == "" {
			domain = "fabric.mesh"
		}

		if node.Hostname != "" {
			_ = RegisterDirectNode(node.Hostname, directAddr, node.Tags, node.Hostname, domain, node.OS, node.Arch)
			_ = RegisterDirectNode(node.Hostname+"."+domain, directAddr, node.Tags, node.Hostname, domain, node.OS, node.Arch)
		}
		if targetHostOnly != "" && targetHostOnly != node.Hostname {
			_ = RegisterDirectNode(targetHostOnly, directAddr, node.Tags, node.Hostname, domain, node.OS, node.Arch)
		}
	}
}

func interactiveKeyPrompt(target string, keys []string) (string, error) {
	fmt.Println("\n[!] SSH Authentication Failed (Permission denied).")
	fmt.Println("\nAvailable SSH keys found in ~/.ssh:")
	for i, key := range keys {
		fmt.Printf("  [%d] %s\n", i+1, key)
	}
	fmt.Printf("  [c] Cancel\n")
	fmt.Printf("\nSelect a key to retry, or press 'c' to cancel: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "c" || input == "C" || input == "" {
		return "", fmt.Errorf("aborted")
	}
	if idx, parseErr := strconv.Atoi(input); parseErr == nil && idx > 0 && idx <= len(keys) {
		chosen := keys[idx-1]
		fmt.Printf("\n[+] Retrying with identity key: %s\n", chosen)
		return chosen, nil
	}
	return "", fmt.Errorf("invalid selection")
}

func runStitch(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return runStitchScan(cmd, "")
	}
	raw := args[0]
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return runStitchScan(cmd, raw)
	}
	return runStitchSingle(cmd, raw)
}

func runStitchSingle(cmd *cobra.Command, rawTarget string) error {
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

	mode, err := resolveStitchMode(stitchModeFlag, stitchRemoteFlag, stitchInvertedFlag)
	if err != nil {
		return err
	}
	if mode == "" {
		if isTerminalInput() {
			mode = promptTopology(false)
		} else {
			mode = "normal"
		}
	}

	listenPort := stitchListenPortFlag
	if listenPort == "" {
		listenPort = "8443"
	}

	serverURL := stitchServerURL
	if serverURL == "" && stitchSocketURL != "" {
		WarnDeprecated("--socket-url", "--server / -s")
		serverURL = stitchSocketURL
	}
	if serverURL == "" {
		serverURL = cfg.Host
	}

	token := stitchTokenFlag
	if token == "" {
		token = cfg.Token
	}

	opts := provision.StitchHostOptions{
		Target:      target,
		SSHPort:     sshPort,
		IdentityKey: stitchIdentityFlag,
		SocketURL:   serverURL,
		Token:       token,
		Domain:      stitchDomainFlag,
		Tags:        parseTags(stitchTagsFlag),
		NoWait:      stitchNoWait,
		Mode:        mode,
		ListenPort:  listenPort,
		NoFallback:  stitchNoFallback,
	}

	provisioner := provision.NewProvisioner(nil, nodeVerifier).
		WithKeyPrompt(interactiveKeyPrompt)

	node, err := provisioner.Provision(opts)
	if err != nil {
		return err
	}

	if node != nil {
		registerInvertedIfApplicable(target, listenPort, node)

		fmt.Println("\n==================================================")
		fmt.Println("        Thread Stitched Successfully!             ")
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

func runStitchScan(cmd *cobra.Command, rawCIDR string) error {
	defaultCIDR := ""
	if rawCIDR == "" {
		var err error
		defaultCIDR, err = provision.GetDefaultLocalCIDR()
		if err != nil {
			return fmt.Errorf("no target specified and failed to auto-detect local subnet: %w", err)
		}
	}

	targets, err := provision.ParseTargets(rawCIDR, defaultCIDR)
	if err != nil {
		return fmt.Errorf("target resolution failed: %w", err)
	}

	var ports []int
	for _, pStr := range strings.Split(stitchPortFlag, ",") {
		pStr = strings.TrimSpace(pStr)
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		ports = []int{22}
	}

	scanOpts := provision.ScanOptions{
		Ports:       ports,
		Concurrency: stitchConcurrencyFlag,
		Timeout:     stitchTimeoutFlag,
	}

	if !stitchQuietFlag && stitchFormatFlag != "json" {
		targetDesc := rawCIDR
		if targetDesc == "" {
			targetDesc = fmt.Sprintf("auto-detected subnet (%d hosts)", len(targets))
		}
		fmt.Printf("[+] Scanning %s for SSH endpoints (ports: %v, workers: %d)...\n", targetDesc, ports, scanOpts.Concurrency)
	}

	discovered, err := provision.ScanTargets(targets, scanOpts, nil)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if stitchQuietFlag || stitchFormatFlag == "json" {
		return FormatDiscoveredOutput(os.Stdout, discovered, stitchQuietFlag, stitchFormatFlag)
	}

	if len(discovered) == 0 {
		fmt.Println("[!] No SSH endpoints discovered.")
		return nil
	}

	fmt.Printf("\n[+] Discovered SSH Hosts (%d found):\n", len(discovered))
	PrintDiscoveryTable(os.Stdout, discovered)
	fmt.Println()

	var selectedTargets []StitchTarget

	if stitchBatchFlag {
		fmt.Println("[+] --batch enabled. Stitching all discovered hosts...")
		for _, h := range discovered {
			selectedTargets = append(selectedTargets, StitchTarget{
				Host:   h.IP,
				Port:   strconv.Itoa(h.Port),
				User:   stitchUserFlag,
				Banner: h.CleanBanner,
			})
		}
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Select hosts to stitch [e.g. 1, admin@2, 3:2222, or 'all', 'q' to quit]: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		selectedTargets, err = ParseSelectionInput(input, discovered, stitchUserFlag)
		if err != nil {
			return fmt.Errorf("selection error: %w", err)
		}

		if len(selectedTargets) == 0 {
			fmt.Println("[*] No hosts selected. Exiting.")
			return nil
		}
	}

	mode, err := resolveStitchMode(stitchModeFlag, stitchRemoteFlag, stitchInvertedFlag)
	if err != nil {
		return err
	}
	if mode == "" {
		if isTerminalInput() && !stitchBatchFlag {
			mode = promptTopology(true)
		} else {
			mode = "normal"
		}
	}

	listenPort := stitchListenPortFlag
	if listenPort == "" {
		listenPort = "8443"
	}

	cfg := GetConfig()
	serverURL := stitchServerURL
	if serverURL == "" && stitchSocketURL != "" {
		WarnDeprecated("--socket-url", "--server / -s")
		serverURL = stitchSocketURL
	}
	if serverURL == "" {
		serverURL = cfg.Host
	}

	token := stitchTokenFlag
	if token == "" {
		token = cfg.Token
	}

	fmt.Printf("\n[+] Starting batch stitch of %d selected host(s) (mode: %s)...\n\n", len(selectedTargets), mode)

	var batchOpts []provision.StitchHostOptions
	for _, st := range selectedTargets {
		opts := provision.StitchHostOptions{
			Target:      st.Host,
			SSHPort:     st.Port,
			IdentityKey: stitchIdentityFlag,
			SocketURL:   serverURL,
			Token:       token,
			Domain:      stitchDomainFlag,
			Tags:        parseTags(stitchTagsFlag),
			NoWait:      stitchNoWait,
			Mode:        mode,
			ListenPort:  listenPort,
			NoFallback:  stitchNoFallback,
		}
		if st.User != "" {
			opts.Target = st.User + "@" + st.Host
		}
		batchOpts = append(batchOpts, opts)
	}

	provisioner := provision.NewProvisioner(nil, nodeVerifier).
		WithKeyPrompt(interactiveKeyPrompt).
		WithProgress(func(current, total int, target, msg string) {
			if !stitchQuietFlag {
				fmt.Printf("[%d/%d] %s: %s\n", current, total, target, msg)
			}
		})
	results, _ := provisioner.ProvisionBatch(batchOpts)

	fmt.Println("\n==================================================")
	fmt.Println("             Batch Stitch Summary                 ")
	fmt.Println("==================================================")
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
			if r.Node != nil {
				registerInvertedIfApplicable(r.Target, listenPort, r.Node)
			}
			fmt.Printf(" [✓] %-25s -> %s (Online)\n", r.Target, r.Hostname)
		} else {
			fmt.Printf(" [✗] %-25s -> Failed: %v\n", r.Target, r.Error)
		}
	}
	fmt.Println("==================================================")
	fmt.Printf("Total: %d | Joined: %d | Failed: %d\n\n", len(results), successCount, len(results)-successCount)

	return nil
}
