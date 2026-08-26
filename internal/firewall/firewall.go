package firewall

import (
	"fmt"
	"os/exec"
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

// Manager handles detection, command formatting, and execution of firewall rules across backends.
type Manager struct {
	runner CommandRunner
}

// NewManager creates a Manager targeting the host environment.
func NewManager() *Manager {
	return &Manager{
		runner: &osCommandRunner{},
	}
}

// NewManagerWithRunner creates a Manager with a custom CommandRunner for testing.
func NewManagerWithRunner(runner CommandRunner) *Manager {
	return &Manager{
		runner: runner,
	}
}

// DetectBackend probes for active Linux firewall backends in priority order:
// 1. UFW (if active)
// 2. Firewalld (if active/running)
// 3. NFTables (if binary present)
// 4. IPTables (fallback standard packet filter)
func (m *Manager) DetectBackend() Backend {
	// 1. UFW
	if _, err := m.runner.LookPath("ufw"); err == nil {
		out, err := m.runner.Run("ufw", "status")
		if err == nil && strings.Contains(strings.ToLower(string(out)), "status: active") {
			return BackendUFW
		}
	}

	// 2. Firewalld
	if _, err := m.runner.LookPath("firewall-cmd"); err == nil {
		out, err := m.runner.Run("firewall-cmd", "--state")
		if err == nil && strings.Contains(strings.ToLower(string(out)), "running") {
			return BackendFirewalld
		}
	}

	// 3. NFTables
	if _, err := m.runner.LookPath("nft"); err == nil {
		return BackendNFTables
	}

	// 4. IPTables
	if _, err := m.runner.LookPath("iptables"); err == nil {
		return BackendIPTables
	}

	return BackendNone
}

// GetOpenPortCommands returns the command strings required to open a port on the specified backend.
func (m *Manager) GetOpenPortCommands(backend Backend, port int, proto, comment string) []string {
	if proto == "" {
		proto = "tcp"
	}
	proto = strings.ToLower(proto)

	switch backend {
	case BackendUFW:
		if comment != "" {
			return []string{fmt.Sprintf("ufw allow %d/%s comment %q", port, proto, comment)}
		}
		return []string{fmt.Sprintf("ufw allow %d/%s", port, proto)}

	case BackendFirewalld:
		return []string{
			fmt.Sprintf("firewall-cmd --permanent --add-port=%d/%s", port, proto),
			"firewall-cmd --reload",
		}

	case BackendNFTables:
		if comment != "" {
			return []string{fmt.Sprintf("nft add rule inet filter input %s dport %d accept comment %q", proto, port, comment)}
		}
		return []string{fmt.Sprintf("nft add rule inet filter input %s dport %d accept", proto, port)}

	case BackendIPTables:
		if comment != "" {
			return []string{fmt.Sprintf("iptables -I INPUT -p %s --dport %d -m comment --comment %q -j ACCEPT", proto, port, comment)}
		}
		return []string{fmt.Sprintf("iptables -I INPUT -p %s --dport %d -j ACCEPT", proto, port)}

	default:
		return nil
	}
}

// GetClosePortCommands returns the command strings required to close/delete a port rule on the specified backend.
func (m *Manager) GetClosePortCommands(backend Backend, port int, proto string) []string {
	if proto == "" {
		proto = "tcp"
	}
	proto = strings.ToLower(proto)

	switch backend {
	case BackendUFW:
		return []string{fmt.Sprintf("ufw delete allow %d/%s", port, proto)}

	case BackendFirewalld:
		return []string{
			fmt.Sprintf("firewall-cmd --permanent --remove-port=%d/%s", port, proto),
			"firewall-cmd --reload",
		}

	case BackendNFTables:
		return []string{fmt.Sprintf("nft delete rule inet filter input %s dport %d accept", proto, port)}

	case BackendIPTables:
		return []string{fmt.Sprintf("iptables -D INPUT -p %s --dport %d -j ACCEPT", proto, port)}

	default:
		return nil
	}
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
	if proto == "" {
		proto = "tcp"
	}
	proto = strings.ToLower(proto)

	switch backend {
	case BackendUFW:
		var args []string
		if comment != "" {
			args = []string{"allow", fmt.Sprintf("%d/%s", port, proto), "comment", comment}
		} else {
			args = []string{"allow", fmt.Sprintf("%d/%s", port, proto)}
		}
		out, err := m.runner.Run("ufw", args...)
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "ufw " + strings.Join(args, " "),
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	case BackendFirewalld:
		out, err := m.runner.Run("firewall-cmd", "--permanent", fmt.Sprintf("--add-port=%d/%s", port, proto))
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: fmt.Sprintf("firewall-cmd --permanent --add-port=%d/%s", port, proto),
				Output:  string(out),
				Err:     err,
			}
		}
		out, err = m.runner.Run("firewall-cmd", "--reload")
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "firewall-cmd --reload",
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	case BackendNFTables:
		var args []string
		if comment != "" {
			args = []string{"add", "rule", "inet", "filter", "input", proto, "dport", fmt.Sprintf("%d", port), "accept", "comment", comment}
		} else {
			args = []string{"add", "rule", "inet", "filter", "input", proto, "dport", fmt.Sprintf("%d", port), "accept"}
		}
		out, err := m.runner.Run("nft", args...)
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "nft " + strings.Join(args, " "),
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	case BackendIPTables:
		var args []string
		if comment != "" {
			args = []string{"-I", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"}
		} else {
			args = []string{"-I", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		}
		out, err := m.runner.Run("iptables", args...)
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "iptables " + strings.Join(args, " "),
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	default:
		return nil
	}
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
	if proto == "" {
		proto = "tcp"
	}
	proto = strings.ToLower(proto)

	switch backend {
	case BackendUFW:
		args := []string{"delete", "allow", fmt.Sprintf("%d/%s", port, proto)}
		out, err := m.runner.Run("ufw", args...)
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "ufw " + strings.Join(args, " "),
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	case BackendFirewalld:
		out, err := m.runner.Run("firewall-cmd", "--permanent", fmt.Sprintf("--remove-port=%d/%s", port, proto))
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: fmt.Sprintf("firewall-cmd --permanent --remove-port=%d/%s", port, proto),
				Output:  string(out),
				Err:     err,
			}
		}
		out, err = m.runner.Run("firewall-cmd", "--reload")
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "firewall-cmd --reload",
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	case BackendNFTables:
		args := []string{"delete", "rule", "inet", "filter", "input", proto, "dport", fmt.Sprintf("%d", port), "accept"}
		out, err := m.runner.Run("nft", args...)
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "nft " + strings.Join(args, " "),
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	case BackendIPTables:
		args := []string{"-D", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		out, err := m.runner.Run("iptables", args...)
		if err != nil {
			return &PermissionError{
				Backend: backend,
				Command: "iptables " + strings.Join(args, " "),
				Output:  string(out),
				Err:     err,
			}
		}
		return nil

	default:
		return nil
	}
}
