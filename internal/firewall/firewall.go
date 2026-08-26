package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Backend represents a supported Linux firewall system.
type Backend string

const (
	BackendNone      Backend = ""
	BackendUFW       Backend = "ufw"
	BackendFirewalld Backend = "firewalld"
	BackendNFTables  Backend = "nftables"
	BackendIPTables  Backend = "iptables"
)

// CommandRunner abstracts shell execution for testing and mocking.
type CommandRunner interface {
	Run(name string, args ...string) ([]byte, error)
	LookPath(file string) (string, error)
}

type osCommandRunner struct{}

func (r *osCommandRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func (r *osCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// PermissionError indicates that elevated privileges (e.g. sudo) are required.
type PermissionError struct {
	Backend Backend
	Command string
	Output  string
	Err     error
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("permission denied executing %s firewall command (%s): %s", e.Backend, e.Command, strings.TrimSpace(e.Output))
}

func (e *PermissionError) Unwrap() error {
	return e.Err
}

// Driver defines backend-specific firewall operations.
type Driver interface {
	Detect(runner CommandRunner) bool
	GetOpenCommands(port int, proto, comment string) []string
	GetCloseCommands(port int, proto, comment string) []string
	Open(runner CommandRunner, port int, proto, comment string) error
	Close(runner CommandRunner, port int, proto, comment string) error
}

// UFWDriver handles Ubuntu/Debian Uncomplicated Firewall.
type UFWDriver struct{}

func (d *UFWDriver) Detect(runner CommandRunner) bool {
	if _, err := runner.LookPath("ufw"); err != nil {
		return false
	}
	out, err := runner.Run("ufw", "status")
	return err == nil && strings.Contains(strings.ToLower(string(out)), "status: active")
}

func (d *UFWDriver) GetOpenCommands(port int, proto, comment string) []string {
	if comment != "" {
		return []string{fmt.Sprintf("ufw allow %d/%s comment %q", port, proto, comment)}
	}
	return []string{fmt.Sprintf("ufw allow %d/%s", port, proto)}
}

func (d *UFWDriver) GetCloseCommands(port int, proto, comment string) []string {
	return []string{fmt.Sprintf("ufw delete allow %d/%s", port, proto)}
}

func (d *UFWDriver) Open(runner CommandRunner, port int, proto, comment string) error {
	var args []string
	if comment != "" {
		args = []string{"allow", fmt.Sprintf("%d/%s", port, proto), "comment", comment}
	} else {
		args = []string{"allow", fmt.Sprintf("%d/%s", port, proto)}
	}
	out, err := runner.Run("ufw", args...)
	if err != nil {
		return &PermissionError{
			Backend: BackendUFW,
			Command: "ufw " + strings.Join(args, " "),
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

func (d *UFWDriver) Close(runner CommandRunner, port int, proto, comment string) error {
	args := []string{"delete", "allow", fmt.Sprintf("%d/%s", port, proto)}
	out, err := runner.Run("ufw", args...)
	if err != nil {
		return &PermissionError{
			Backend: BackendUFW,
			Command: "ufw " + strings.Join(args, " "),
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

// FirewalldDriver handles RHEL/CentOS/Fedora Firewalld daemon.
type FirewalldDriver struct{}

func (d *FirewalldDriver) Detect(runner CommandRunner) bool {
	if _, err := runner.LookPath("firewall-cmd"); err != nil {
		return false
	}
	out, err := runner.Run("firewall-cmd", "--state")
	return err == nil && strings.Contains(strings.ToLower(string(out)), "running")
}

func (d *FirewalldDriver) GetOpenCommands(port int, proto, comment string) []string {
	return []string{
		fmt.Sprintf("firewall-cmd --permanent --add-port=%d/%s", port, proto),
		"firewall-cmd --reload",
	}
}

func (d *FirewalldDriver) GetCloseCommands(port int, proto, comment string) []string {
	return []string{
		fmt.Sprintf("firewall-cmd --permanent --remove-port=%d/%s", port, proto),
		"firewall-cmd --reload",
	}
}

func (d *FirewalldDriver) Open(runner CommandRunner, port int, proto, comment string) error {
	out, err := runner.Run("firewall-cmd", "--permanent", fmt.Sprintf("--add-port=%d/%s", port, proto))
	if err != nil {
		return &PermissionError{
			Backend: BackendFirewalld,
			Command: fmt.Sprintf("firewall-cmd --permanent --add-port=%d/%s", port, proto),
			Output:  string(out),
			Err:     err,
		}
	}
	out, err = runner.Run("firewall-cmd", "--reload")
	if err != nil {
		return &PermissionError{
			Backend: BackendFirewalld,
			Command: "firewall-cmd --reload",
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

func (d *FirewalldDriver) Close(runner CommandRunner, port int, proto, comment string) error {
	out, err := runner.Run("firewall-cmd", "--permanent", fmt.Sprintf("--remove-port=%d/%s", port, proto))
	if err != nil {
		return &PermissionError{
			Backend: BackendFirewalld,
			Command: fmt.Sprintf("firewall-cmd --permanent --remove-port=%d/%s", port, proto),
			Output:  string(out),
			Err:     err,
		}
	}
	out, err = runner.Run("firewall-cmd", "--reload")
	if err != nil {
		return &PermissionError{
			Backend: BackendFirewalld,
			Command: "firewall-cmd --reload",
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

// NFTablesDriver handles modern Linux NFTables packet filter.
type NFTablesDriver struct{}

func (d *NFTablesDriver) Detect(runner CommandRunner) bool {
	if _, err := runner.LookPath("nft"); err != nil {
		return false
	}
	out, err := runner.Run("nft", "list", "tables")
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

func (d *NFTablesDriver) GetOpenCommands(port int, proto, comment string) []string {
	if comment != "" {
		return []string{fmt.Sprintf("nft add rule inet filter input %s dport %d accept comment %q", proto, port, comment)}
	}
	return []string{fmt.Sprintf("nft add rule inet filter input %s dport %d accept", proto, port)}
}

func (d *NFTablesDriver) GetCloseCommands(port int, proto, comment string) []string {
	return []string{fmt.Sprintf("nft delete rule inet filter input $(nft -a list chain inet filter input 2>/dev/null | grep -E '\\bdport\\s+%d\\b' | awk '{print \"handle\", $NF}')", port)}
}

func (d *NFTablesDriver) Open(runner CommandRunner, port int, proto, comment string) error {
	var args []string
	if comment != "" {
		args = []string{"add", "rule", "inet", "filter", "input", proto, "dport", fmt.Sprintf("%d", port), "accept", "comment", comment}
	} else {
		args = []string{"add", "rule", "inet", "filter", "input", proto, "dport", fmt.Sprintf("%d", port), "accept"}
	}
	out, err := runner.Run("nft", args...)
	if err != nil {
		return &PermissionError{
			Backend: BackendNFTables,
			Command: "nft " + strings.Join(args, " "),
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

var handleRegex = regexp.MustCompile(`handle\s+(\d+)`)

func (d *NFTablesDriver) Close(runner CommandRunner, port int, proto, comment string) error {
	// Look up rule handles in inet filter input
	out, err := runner.Run("nft", "-a", "list", "chain", "inet", "filter", "input")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		portRegex := regexp.MustCompile(fmt.Sprintf(`\bdport\s+%d\b`, port))
		for scanner.Scan() {
			line := scanner.Text()
			if portRegex.MatchString(line) {
				matches := handleRegex.FindStringSubmatch(line)
				if len(matches) > 1 {
					handleID := matches[1]
					args := []string{"delete", "rule", "inet", "filter", "input", "handle", handleID}
					delOut, delErr := runner.Run("nft", args...)
					if delErr != nil {
						return &PermissionError{
							Backend: BackendNFTables,
							Command: "nft " + strings.Join(args, " "),
							Output:  string(delOut),
							Err:     delErr,
						}
					}
					return nil
				}
			}
		}
	}

	// Fallback direct attempt if listing was not possible or no handle found
	args := []string{"delete", "rule", "inet", "filter", "input", proto, "dport", fmt.Sprintf("%d", port), "accept"}
	out, err = runner.Run("nft", args...)
	if err != nil {
		return &PermissionError{
			Backend: BackendNFTables,
			Command: "nft " + strings.Join(args, " "),
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

// IPTablesDriver handles legacy Linux Netfilter iptables.
type IPTablesDriver struct{}

func (d *IPTablesDriver) Detect(runner CommandRunner) bool {
	if _, err := runner.LookPath("iptables"); err != nil {
		return false
	}
	out, err := runner.Run("iptables", "-S", "INPUT")
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A INPUT") || strings.HasPrefix(l, "-I INPUT") {
			return true
		}
	}
	return false
}

func (d *IPTablesDriver) GetOpenCommands(port int, proto, comment string) []string {
	if comment != "" {
		return []string{fmt.Sprintf("iptables -I INPUT -p %s --dport %d -m comment --comment %q -j ACCEPT", proto, port, comment)}
	}
	return []string{fmt.Sprintf("iptables -I INPUT -p %s --dport %d -j ACCEPT", proto, port)}
}

func (d *IPTablesDriver) GetCloseCommands(port int, proto, comment string) []string {
	if comment != "" {
		return []string{fmt.Sprintf("iptables -D INPUT -p %s --dport %d -m comment --comment %q -j ACCEPT", proto, port, comment)}
	}
	return []string{fmt.Sprintf("iptables -D INPUT -p %s --dport %d -j ACCEPT", proto, port)}
}

func (d *IPTablesDriver) Open(runner CommandRunner, port int, proto, comment string) error {
	var args []string
	if comment != "" {
		args = []string{"-I", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"}
	} else {
		args = []string{"-I", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	}
	out, err := runner.Run("iptables", args...)
	if err != nil {
		return &PermissionError{
			Backend: BackendIPTables,
			Command: "iptables " + strings.Join(args, " "),
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

func (d *IPTablesDriver) Close(runner CommandRunner, port int, proto, comment string) error {
	var args []string
	if comment != "" {
		args = []string{"-D", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"}
		_, err := runner.Run("iptables", args...)
		if err == nil {
			return nil
		}
	}
	// Fallback to without comment if comment matching failed
	args = []string{"-D", "INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	out, err := runner.Run("iptables", args...)
	if err != nil {
		return &PermissionError{
			Backend: BackendIPTables,
			Command: "iptables " + strings.Join(args, " "),
			Output:  string(out),
			Err:     err,
		}
	}
	return nil
}

// Manager handles detection, command formatting, and execution of firewall rules across backends.
type Manager struct {
	runner  CommandRunner
	drivers map[Backend]Driver
}

// NewManager creates a Manager targeting the host environment.
func NewManager() *Manager {
	return NewManagerWithRunner(&osCommandRunner{})
}

// NewManagerWithRunner creates a Manager with a custom CommandRunner for testing.
func NewManagerWithRunner(runner CommandRunner) *Manager {
	return &Manager{
		runner: runner,
		drivers: map[Backend]Driver{
			BackendUFW:       &UFWDriver{},
			BackendFirewalld: &FirewalldDriver{},
			BackendNFTables:  &NFTablesDriver{},
			BackendIPTables:  &IPTablesDriver{},
		},
	}
}

// DetectBackend probes for active Linux firewall backends in priority order:
// 1. UFW (if active)
// 2. Firewalld (if active/running)
// 3. NFTables (if active tables exist)
// 4. IPTables (if active filter rules exist)
func (m *Manager) DetectBackend() Backend {
	priority := []Backend{BackendUFW, BackendFirewalld, BackendNFTables, BackendIPTables}
	for _, b := range priority {
		if driver, ok := m.drivers[b]; ok && driver.Detect(m.runner) {
			return b
		}
	}
	return BackendNone
}

func (m *Manager) normalizeProto(proto string) string {
	if proto == "" {
		return "tcp"
	}
	return strings.ToLower(proto)
}

// GetOpenPortCommands returns the command strings required to open a port on the specified backend.
func (m *Manager) GetOpenPortCommands(backend Backend, port int, proto, comment string) []string {
	if driver, ok := m.drivers[backend]; ok {
		return driver.GetOpenCommands(port, m.normalizeProto(proto), comment)
	}
	return nil
}

// GetClosePortCommands returns the command strings required to close/delete a port rule on the specified backend.
func (m *Manager) GetClosePortCommands(backend Backend, port int, proto string) []string {
	return m.GetClosePortCommandsWithComment(backend, port, proto, "")
}

// GetClosePortCommandsWithComment returns the command strings required to close/delete a port rule with comment.
func (m *Manager) GetClosePortCommandsWithComment(backend Backend, port int, proto, comment string) []string {
	if driver, ok := m.drivers[backend]; ok {
		return driver.GetCloseCommands(port, m.normalizeProto(proto), comment)
	}
	return nil
}

// GetOpenPortManualInstructions returns copy-pasteable sudo instructions for opening a port.
func (m *Manager) GetOpenPortManualInstructions(backend Backend, port int, proto, comment string) string {
	cmds := m.GetOpenPortCommands(backend, port, proto, comment)
	if len(cmds) == 0 {
		return ""
	}
	var sudoCmds []string
	for _, c := range cmds {
		sudoCmds = append(sudoCmds, "sudo "+c)
	}
	return strings.Join(sudoCmds, " && ")
}

// GetClosePortManualInstructions returns copy-pasteable sudo instructions for closing a port.
func (m *Manager) GetClosePortManualInstructions(backend Backend, port int, proto string) string {
	cmds := m.GetClosePortCommands(backend, port, proto)
	if len(cmds) == 0 {
		return ""
	}
	var sudoCmds []string
	for _, c := range cmds {
		sudoCmds = append(sudoCmds, "sudo "+c)
	}
	return strings.Join(sudoCmds, " && ")
}

// OpenPort detects the active firewall backend and opens the specified port.
func (m *Manager) OpenPort(port int, proto, comment string) error {
	backend := m.DetectBackend()
	if backend == BackendNone {
		return nil
	}
	return m.OpenPortWithBackend(backend, port, proto, comment)
}

// OpenPortWithBackend executes open port commands on the specified backend.
func (m *Manager) OpenPortWithBackend(backend Backend, port int, proto, comment string) error {
	if driver, ok := m.drivers[backend]; ok {
		return driver.Open(m.runner, port, m.normalizeProto(proto), comment)
	}
	return nil
}

// ClosePort detects the active firewall backend and closes the specified port.
func (m *Manager) ClosePort(port int, proto string) error {
	backend := m.DetectBackend()
	if backend == BackendNone {
		return nil
	}
	return m.ClosePortWithBackend(backend, port, proto)
}

// ClosePortWithBackend executes close/delete port commands on the specified backend.
func (m *Manager) ClosePortWithBackend(backend Backend, port int, proto string) error {
	return m.ClosePortWithBackendAndComment(backend, port, proto, "")
}

// ClosePortWithBackendAndComment executes close/delete port commands with optional comment matching.
func (m *Manager) ClosePortWithBackendAndComment(backend Backend, port int, proto, comment string) error {
	if driver, ok := m.drivers[backend]; ok {
		return driver.Close(m.runner, port, m.normalizeProto(proto), comment)
	}
	return nil
}
