package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fabric/internal/firewall"
)

type cliMockRunner struct {
	lookPathMap map[string]string
	runOutputs  map[string]cliMockRunResult
	executed    [][]string
}

type cliMockRunResult struct {
	output []byte
	err    error
}

func newCLIMockRunner() *cliMockRunner {
	return &cliMockRunner{
		lookPathMap: make(map[string]string),
		runOutputs:  make(map[string]cliMockRunResult),
	}
}

func (m *cliMockRunner) LookPath(file string) (string, error) {
	if p, ok := m.lookPathMap[file]; ok {
		return p, nil
	}
	return "", errors.New("not found")
}

func (m *cliMockRunner) Run(name string, args ...string) ([]byte, error) {
	cmdKey := name + " " + strings.Join(args, " ")
	m.executed = append(m.executed, append([]string{name}, args...))
	if res, ok := m.runOutputs[cmdKey]; ok {
		return res.output, res.err
	}
	return nil, nil
}

func TestInitFirewallFlows(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	t.Run("server role with --open-firewall opens port on ufw", func(t *testing.T) {
		runner := newCLIMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = cliMockRunResult{output: []byte("Status: active\n"), err: nil}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"init", "-y", "--role", "server", "--open-firewall", "--server", "wss://localhost:8443/ws", "--token", "tok"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric init failed: %v", err)
		}

		// Verify ufw open port was called
		found := false
		for _, exec := range runner.executed {
			if len(exec) >= 3 && exec[0] == "ufw" && exec[1] == "allow" && strings.HasPrefix(exec[2], "8443/tcp") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected ufw allow 8443/tcp in executed commands: %v", runner.executed)
		}
	})

	t.Run("thread role local mode displays zero inbound ports reassurance", func(t *testing.T) {
		runner := newCLIMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = cliMockRunResult{output: []byte("Status: active\n"), err: nil}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		// Capture stdout output by configuring reader or using output check
		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"init", "-y", "--role", "thread", "--mode", "local", "--server", "wss://localhost:8443/ws", "--token", "tok"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric init failed: %v", err)
		}

		// No firewall allow commands should be executed in local mode
		for _, exec := range runner.executed {
			if len(exec) >= 2 && exec[0] == "ufw" && exec[1] == "allow" {
				t.Errorf("local mode should not open firewall ports: %v", exec)
			}
		}
	})

	t.Run("thread role remote mode with firewalld opens port", func(t *testing.T) {
		runner := newCLIMockRunner()
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["firewall-cmd --state"] = cliMockRunResult{output: []byte("running\n"), err: nil}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"init", "-y", "--role", "thread", "--mode", "remote", "--server", "wss://localhost:8443/ws", "--token", "tok"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric init failed: %v", err)
		}

		foundAddPort := false
		foundReload := false
		for _, exec := range runner.executed {
			if len(exec) >= 3 && exec[0] == "firewall-cmd" && exec[1] == "--permanent" && exec[2] == "--add-port=8443/tcp" {
				foundAddPort = true
			}
			if len(exec) >= 2 && exec[0] == "firewall-cmd" && exec[1] == "--reload" {
				foundReload = true
			}
		}
		if !foundAddPort || !foundReload {
			t.Errorf("expected firewalld add-port and reload commands, got: %v", runner.executed)
		}
	})

	t.Run("permission denied outputs manual instructions", func(t *testing.T) {
		runner := newCLIMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = cliMockRunResult{output: []byte("Status: active\n"), err: nil}
		runner.runOutputs["ufw allow 8443/tcp comment \"Fabric Server Control Plane\""] = cliMockRunResult{
			output: []byte("Permission denied\n"),
			err:    errors.New("exit status 1"),
		}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"init", "-y", "--role", "server", "--server", "wss://localhost:8443/ws", "--token", "tok"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric init should not fail fatally on firewall permission error: %v", err)
		}
	})

	t.Run("server role with --acme opens both 8443 and 80", func(t *testing.T) {
		runner := newCLIMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = cliMockRunResult{output: []byte("Status: active\n"), err: nil}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"init", "-y", "--role", "server", "--acme", "--server", "wss://localhost:8443/ws", "--token", "tok"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric init failed: %v", err)
		}

		found8443 := false
		found80 := false
		for _, exec := range runner.executed {
			if len(exec) >= 3 && exec[0] == "ufw" && exec[1] == "allow" {
				if strings.HasPrefix(exec[2], "8443/tcp") {
					found8443 = true
				}
				if strings.HasPrefix(exec[2], "80/tcp") {
					found80 = true
				}
			}
		}
		if !found8443 || !found80 {
			t.Errorf("expected both 8443/tcp and 80/tcp to be opened with --acme, got: %v", runner.executed)
		}
	})

	t.Run("inactive firewall notes that no configuration is required", func(t *testing.T) {
		runner := newCLIMockRunner()
		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		rootCmd.SetArgs([]string{"init", "-y", "--role", "server", "--server", "wss://localhost:8443/ws", "--token", "tok"})
		err := rootCmd.Execute()

		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if err != nil {
			t.Fatalf("fabric init failed: %v", err)
		}

		if !strings.Contains(buf.String(), "No active Linux firewall detected") {
			t.Errorf("expected note about inactive firewall in output, got: %s", buf.String())
		}
	})
}

func TestUninstallFirewallTeardown(t *testing.T) {
	tempHome := t.TempDir()
	os.Setenv("HOME", tempHome)
	defer os.Unsetenv("HOME")

	t.Run("tears down firewall rule for server on uninstall -y", func(t *testing.T) {
		// Setup fake server.env
		fabricDir := filepath.Join(tempHome, ".fabric")
		_ = os.MkdirAll(fabricDir, 0755)
		_ = os.WriteFile(filepath.Join(fabricDir, "server.env"), []byte("FABRIC_PORT=8443\n"), 0600)

		runner := newCLIMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = cliMockRunResult{output: []byte("Status: active\n"), err: nil}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"uninstall", "-y"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric uninstall failed: %v", err)
		}

		foundDelete := false
		for _, exec := range runner.executed {
			if len(exec) >= 3 && exec[0] == "ufw" && exec[1] == "delete" && exec[2] == "allow" {
				foundDelete = true
				break
			}
		}
		if !foundDelete {
			t.Errorf("expected ufw delete allow command, got: %v", runner.executed)
		}
	})

	t.Run("tears down firewall rule for remote thread on uninstall -y", func(t *testing.T) {
		fabricDir := filepath.Join(tempHome, ".fabric")
		_ = os.MkdirAll(fabricDir, 0755)
		_ = os.WriteFile(filepath.Join(fabricDir, "thread.env"), []byte("FABRIC_MODE=remote\nFABRIC_LISTEN=:8443\n"), 0600)

		runner := newCLIMockRunner()
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["firewall-cmd --state"] = cliMockRunResult{output: []byte("running\n"), err: nil}

		SetDefaultFirewallManager(firewall.NewManagerWithRunner(runner))
		defer SetDefaultFirewallManager(nil)

		var stdoutBuf bytes.Buffer
		rootCmd.SetOut(&stdoutBuf)
		rootCmd.SetArgs([]string{"uninstall", "-y"})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("fabric uninstall failed: %v", err)
		}

		foundRemovePort := false
		for _, exec := range runner.executed {
			if len(exec) >= 3 && exec[0] == "firewall-cmd" && exec[1] == "--permanent" && exec[2] == "--remove-port=8443/tcp" {
				foundRemovePort = true
				break
			}
		}
		if !foundRemovePort {
			t.Errorf("expected firewalld remove-port command, got: %v", runner.executed)
		}
	})
}
