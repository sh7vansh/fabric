package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fabric/internal/protocol"
	"fabric/internal/provision"

	"github.com/spf13/cobra"
)

var (
	stitchIdentityFlag string
	stitchPortFlag     string
	stitchSocketURL    string
	stitchTokenFlag    string
	stitchDomainFlag   string
	stitchTagsFlag     string
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
	discoverTagsFlag        string
)

var stitchCmd = &cobra.Command{
	Use:     "stitch [flags] [user@]hostname[:port]",
	Short:   "Bootstrap and stitch a remote host into the Fabric mesh over SSH",
	GroupID: "network",
	SilenceUsage: true,
	Long: `Automate provisioning of remote machines into the Fabric mesh over SSH.

The command connects via SSH, installs the fabric-node binary, creates systemd units,
configures environment variables with cluster tokens, and verifies active mesh connection.`,
	Example: `  # Stitch a remote machine with default SSH credentials
  fabric stitch root@192.168.1.50

  # Stitch using a specific SSH key, port, and custom tags
  fabric stitch -i ~/.ssh/id_ed25519 -p 2222 --tags web,prod ubuntu@10.0.0.12

  # Scan network and batch stitch discovered machines
  fabric stitch discover 192.168.1.0/24`,
	Args: cobra.ExactArgs(1),
	RunE: runStitch,
}

var stitchDiscoverCmd = &cobra.Command{
	Use:   "discover [flags] [CIDR]",
	Short: "Scan local or specified network for SSH endpoints and batch stitch into the mesh",
	SilenceUsage: true,
	Long: `Scan a CIDR block for open SSH ports, prompt for host selection, and automatically
stitch the selected machines into the Fabric mesh.`,
	Example: `  # Scan default local interface subnet
  fabric stitch discover

  # Scan specific CIDR block
  fabric stitch discover 192.168.1.0/24

  # Scan with custom SSH port and default user
  fabric stitch discover -p 22,2222 -u ubuntu --tags worker 10.0.0.0/24`,
	Args: cobra.MaximumNArgs(1),
	RunE: runStitchDiscover,
}

func init() {
	rootCmd.AddCommand(stitchCmd)
	stitchCmd.AddCommand(stitchDiscoverCmd)

	stitchCmd.Flags().StringVarP(&stitchIdentityFlag, "identity", "i", "", "SSH identity key file")
	stitchCmd.Flags().StringVarP(&stitchPortFlag, "port", "p", "22", "SSH port on target host")
	stitchCmd.Flags().StringVar(&stitchSocketURL, "socket-url", "", "Socket URL override (e.g. ws://192.168.1.50:8080/ws)")
	stitchCmd.Flags().StringVar(&stitchTokenFlag, "token", "", "Cluster token override")
	stitchCmd.Flags().StringVar(&stitchDomainFlag, "domain", "fabric.mesh", "Domain to register on the mesh")
	stitchCmd.Flags().StringVar(&stitchTagsFlag, "tags", "", "Comma-separated metadata tags to assign to the node (e.g. web,prod)")
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
	stitchDiscoverCmd.Flags().StringVar(&discoverTagsFlag, "tags", "", "Comma-separated metadata tags to assign to discovered nodes")
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

	opts := provision.StitchHostOptions{
		Target:      target,
		SSHPort:     sshPort,
		IdentityKey: stitchIdentityFlag,
		SocketURL:   stitchSocketURL,
		Token:       stitchTokenFlag,
		Domain:      stitchDomainFlag,
		Tags:        parseTags(stitchTagsFlag),
		NoWait:      stitchNoWait,
	}

	if opts.SocketURL == "" {
		opts.SocketURL = cfg.Host
	}
	if opts.Token == "" {
		opts.Token = cfg.Token
	}

	node, err := provision.ExecuteStitchHost(opts, nil, nodeVerifier)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 255") {
			fmt.Println("\n[!] SSH Authentication Failed (Permission denied).")
			
			home, _ := os.UserHomeDir()
			sshDir := filepath.Join(home, ".ssh")
			files, _ := os.ReadDir(sshDir)
			var keys []string
			for _, f := range files {
				if !f.IsDir() && !strings.HasSuffix(f.Name(), ".pub") && !strings.HasPrefix(f.Name(), "known_hosts") && !strings.HasPrefix(f.Name(), "config") && !strings.HasPrefix(f.Name(), "authorized_keys") {
					keys = append(keys, filepath.Join(sshDir, f.Name()))
				}
			}
			
			if len(keys) > 0 {
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
					return fmt.Errorf("aborted")
				}
				if idx, parseErr := strconv.Atoi(input); parseErr == nil && idx > 0 && idx <= len(keys) {
					opts.IdentityKey = keys[idx-1]
					fmt.Printf("\n[+] Retrying with identity key: %s\n", opts.IdentityKey)
					node, err = provision.ExecuteStitchHost(opts, nil, nodeVerifier)
					if err != nil {
						return fmt.Errorf("retry failed: %w", err)
					}
				} else {
					return fmt.Errorf("invalid selection")
				}
			} else {
				fmt.Println("\nHint: You may need to specify a password or add your SSH key using:")
				fmt.Printf("  ssh-copy-id %s\n", opts.Target)
				return err
			}
		} else {
			return err
		}
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
	for _, pStr := range strings.Split(discoverPortFlag, ",") {
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

	discovered, err := provision.ScanTargets(targets, scanOpts, nil)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

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

		opts := provision.StitchHostOptions{
			Target:      st.Host,
			SSHPort:     st.Port,
			IdentityKey: discoverIdentityFlag,
			SocketURL:   socketURL,
			Token:       token,
			Domain:      discoverDomainFlag,
			Tags:        parseTags(discoverTagsFlag),
			NoWait:      discoverNoWaitFlag,
		}
		if st.User != "" {
			opts.Target = st.User + "@" + st.Host
		}

		node, err := provision.ExecuteStitchHost(opts, nil, nodeVerifier)
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
