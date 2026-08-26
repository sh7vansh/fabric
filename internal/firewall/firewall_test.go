package firewall_test

import (
	"errors"
	"strings"
	"testing"

	"fabric/internal/firewall"
)

type mockRunner struct {
	lookPathMap map[string]string
	runOutputs  map[string]mockRunResult
	executed    [][]string
}

type mockRunResult struct {
	output []byte
	err    error
}

func newMockRunner() *mockRunner {
	return &mockRunner{
		lookPathMap: make(map[string]string),
		runOutputs:  make(map[string]mockRunResult),
	}
}

func (m *mockRunner) LookPath(file string) (string, error) {
	if p, ok := m.lookPathMap[file]; ok {
		return p, nil
	}
	return "", errors.New("command not found")
}

func (m *mockRunner) Run(name string, args ...string) ([]byte, error) {
	cmdKey := name + " " + strings.Join(args, " ")
	m.executed = append(m.executed, append([]string{name}, args...))
	if res, ok := m.runOutputs[cmdKey]; ok {
		return res.output, res.err
	}
	return nil, nil
}

func TestDetectBackendPriority(t *testing.T) {
	t.Run("detects ufw when active", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["ufw status"] = mockRunResult{output: []byte("Status: active\nTo Action From\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		backend := mgr.DetectBackend()
		if backend != firewall.BackendUFW {
			t.Fatalf("expected BackendUFW, got %v", backend)
		}
	})

	t.Run("skips ufw when inactive and falls back to firewalld", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = mockRunResult{output: []byte("Status: inactive\n"), err: nil}
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["firewall-cmd --state"] = mockRunResult{output: []byte("running\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		backend := mgr.DetectBackend()
		if backend != firewall.BackendFirewalld {
			t.Fatalf("expected BackendFirewalld, got %v", backend)
		}
	})

	t.Run("skips firewalld when not running and falls back to nftables when tables exist", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = mockRunResult{output: []byte("Status: inactive\n"), err: nil}
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["firewall-cmd --state"] = mockRunResult{output: []byte("not running\n"), err: errors.New("not running")}
		runner.lookPathMap["nft"] = "/usr/sbin/nft"
		runner.runOutputs["nft list tables"] = mockRunResult{output: []byte("table inet filter\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		backend := mgr.DetectBackend()
		if backend != firewall.BackendNFTables {
			t.Fatalf("expected BackendNFTables, got %v", backend)
		}
	})

	t.Run("falls back to iptables when nftables has no tables and iptables is active", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["nft"] = "/usr/sbin/nft"
		runner.runOutputs["nft list tables"] = mockRunResult{output: []byte(""), err: nil}
		runner.lookPathMap["iptables"] = "/sbin/iptables"
		runner.runOutputs["iptables -S INPUT"] = mockRunResult{output: []byte("-P INPUT ACCEPT\n-A INPUT -j DROP\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		backend := mgr.DetectBackend()
		if backend != firewall.BackendIPTables {
			t.Fatalf("expected BackendIPTables, got %v", backend)
		}
	})

	t.Run("returns BackendNone when iptables exists but has no active firewall rules", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["iptables"] = "/sbin/iptables"
		runner.runOutputs["iptables -S INPUT"] = mockRunResult{output: []byte("-P INPUT ACCEPT\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		backend := mgr.DetectBackend()
		if backend != firewall.BackendNone {
			t.Fatalf("expected BackendNone, got %v", backend)
		}
	})

	t.Run("returns BackendNone when no firewalls detected", func(t *testing.T) {
		runner := newMockRunner()
		mgr := firewall.NewManagerWithRunner(runner)
		backend := mgr.DetectBackend()
		if backend != firewall.BackendNone {
			t.Fatalf("expected BackendNone, got %v", backend)
		}
	})
}

func TestOpenPortCommands(t *testing.T) {
	runner := newMockRunner()
	mgr := firewall.NewManagerWithRunner(runner)

	t.Run("UFW open port with comment", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendUFW, 8443, "tcp", "Fabric Server Control Plane")
		if len(cmds) != 1 {
			t.Fatalf("expected 1 command, got %d", len(cmds))
		}
		expected := "ufw allow 8443/tcp comment \"Fabric Server Control Plane\""
		if cmds[0] != expected {
			t.Errorf("expected %q, got %q", expected, cmds[0])
		}
	})

	t.Run("UFW open port without comment", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendUFW, 8443, "tcp", "")
		if len(cmds) != 1 || cmds[0] != "ufw allow 8443/tcp" {
			t.Errorf("unexpected command: %v", cmds)
		}
	})

	t.Run("Firewalld open port reload sequence", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendFirewalld, 8443, "tcp", "Fabric Server")
		if len(cmds) != 2 {
			t.Fatalf("expected 2 commands, got %d", len(cmds))
		}
		if cmds[0] != "firewall-cmd --permanent --add-port=8443/tcp" {
			t.Errorf("unexpected cmd[0]: %s", cmds[0])
		}
		if cmds[1] != "firewall-cmd --reload" {
			t.Errorf("unexpected cmd[1]: %s", cmds[1])
		}
	})

	t.Run("NFTables open port with comment", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendNFTables, 8443, "tcp", "Fabric Server")
		if len(cmds) != 1 {
			t.Fatalf("expected 1 command, got %d", len(cmds))
		}
		expected := "nft add rule inet filter input tcp dport 8443 accept comment \"Fabric Server\""
		if cmds[0] != expected {
			t.Errorf("expected %q, got %q", expected, cmds[0])
		}
	})

	t.Run("NFTables open port without comment", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendNFTables, 8443, "tcp", "")
		if len(cmds) != 1 || cmds[0] != "nft add rule inet filter input tcp dport 8443 accept" {
			t.Errorf("unexpected command: %v", cmds)
		}
	})

	t.Run("IPTables open port with comment", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendIPTables, 8443, "tcp", "Fabric Server")
		if len(cmds) != 1 {
			t.Fatalf("expected 1 command, got %d", len(cmds))
		}
		expected := "iptables -I INPUT -p tcp --dport 8443 -m comment --comment \"Fabric Server\" -j ACCEPT"
		if cmds[0] != expected {
			t.Errorf("expected %q, got %q", expected, cmds[0])
		}
	})

	t.Run("IPTables open port without comment", func(t *testing.T) {
		cmds := mgr.GetOpenPortCommands(firewall.BackendIPTables, 8443, "tcp", "")
		if len(cmds) != 1 || cmds[0] != "iptables -I INPUT -p tcp --dport 8443 -j ACCEPT" {
			t.Errorf("unexpected command: %v", cmds)
		}
	})
}

func TestClosePortCommands(t *testing.T) {
	runner := newMockRunner()
	mgr := firewall.NewManagerWithRunner(runner)

	t.Run("UFW close port", func(t *testing.T) {
		cmds := mgr.GetClosePortCommands(firewall.BackendUFW, 8443, "tcp")
		if len(cmds) != 1 || cmds[0] != "ufw delete allow 8443/tcp" {
			t.Errorf("unexpected UFW close command: %v", cmds)
		}
	})

	t.Run("Firewalld close port", func(t *testing.T) {
		cmds := mgr.GetClosePortCommands(firewall.BackendFirewalld, 8443, "tcp")
		if len(cmds) != 2 || cmds[0] != "firewall-cmd --permanent --remove-port=8443/tcp" || cmds[1] != "firewall-cmd --reload" {
			t.Errorf("unexpected Firewalld close commands: %v", cmds)
		}
	})

	t.Run("NFTables close port", func(t *testing.T) {
		cmds := mgr.GetClosePortCommands(firewall.BackendNFTables, 8443, "tcp")
		if len(cmds) != 1 || !strings.Contains(cmds[0], "nft") {
			t.Errorf("unexpected NFTables close command: %v", cmds)
		}
	})

	t.Run("IPTables close port with comment", func(t *testing.T) {
		cmds := mgr.GetClosePortCommandsWithComment(firewall.BackendIPTables, 8443, "tcp", "Fabric Server")
		if len(cmds) != 1 || cmds[0] != `iptables -D INPUT -p tcp --dport 8443 -m comment --comment "Fabric Server" -j ACCEPT` {
			t.Errorf("unexpected IPTables close command with comment: %v", cmds)
		}
	})
}

func TestManualInstructions(t *testing.T) {
	runner := newMockRunner()
	mgr := firewall.NewManagerWithRunner(runner)

	t.Run("Firewalld manual open", func(t *testing.T) {
		manual := mgr.GetOpenPortManualInstructions(firewall.BackendFirewalld, 8443, "tcp", "Fabric Server")
		expected := "sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload"
		if manual != expected {
			t.Errorf("expected %q, got %q", expected, manual)
		}
	})

	t.Run("Firewalld manual close", func(t *testing.T) {
		manual := mgr.GetClosePortManualInstructions(firewall.BackendFirewalld, 8443, "tcp")
		expected := "sudo firewall-cmd --permanent --remove-port=8443/tcp && sudo firewall-cmd --reload"
		if manual != expected {
			t.Errorf("expected %q, got %q", expected, manual)
		}
	})

	t.Run("NFTables manual open", func(t *testing.T) {
		manual := mgr.GetOpenPortManualInstructions(firewall.BackendNFTables, 8443, "tcp", "Fabric Server")
		expected := "sudo nft add rule inet filter input tcp dport 8443 accept comment \"Fabric Server\""
		if manual != expected {
			t.Errorf("expected %q, got %q", expected, manual)
		}
	})
}

func TestOpenAndClosePortExecution(t *testing.T) {
	t.Run("successfully opens and closes port on UFW", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["ufw"] = "/usr/sbin/ufw"
		runner.runOutputs["ufw status"] = mockRunResult{output: []byte("Status: active\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		if err := mgr.OpenPort(8443, "tcp", "Fabric Server"); err != nil {
			t.Fatalf("unexpected open error: %v", err)
		}
		if err := mgr.ClosePort(8443, "tcp"); err != nil {
			t.Fatalf("unexpected close error: %v", err)
		}
	})

	t.Run("successfully opens and closes port on Firewalld", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["firewall-cmd --state"] = mockRunResult{output: []byte("running\n"), err: nil}

		mgr := firewall.NewManagerWithRunner(runner)
		if err := mgr.OpenPort(8443, "tcp", "Fabric Server"); err != nil {
			t.Fatalf("unexpected open error: %v", err)
		}
		if err := mgr.ClosePort(8443, "tcp"); err != nil {
			t.Fatalf("unexpected close error: %v", err)
		}
	})

	t.Run("successfully opens and closes port on NFTables", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["nft"] = "/usr/sbin/nft"

		mgr := firewall.NewManagerWithRunner(runner)
		if err := mgr.OpenPort(8443, "tcp", "Fabric Server"); err != nil {
			t.Fatalf("unexpected open error: %v", err)
		}
		if err := mgr.ClosePort(8443, "tcp"); err != nil {
			t.Fatalf("unexpected close error: %v", err)
		}
	})

	t.Run("NFTables exact port token matching isolates adjacent prefix ports", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["nft"] = "/usr/sbin/nft"
		runner.runOutputs["nft list tables"] = mockRunResult{output: []byte("table inet filter\n"), err: nil}

		nftTableOutput := `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 8080 accept # handle 10
		tcp dport 8000 accept # handle 11
		tcp dport 8088 accept # handle 12
		tcp dport 80 accept # handle 13
		tcp dport 8443 accept # handle 14
	}
}`
		runner.runOutputs["nft -a list chain inet filter input"] = mockRunResult{
			output: []byte(nftTableOutput),
			err:    nil,
		}

		mgr := firewall.NewManagerWithRunner(runner)
		if err := mgr.ClosePort(80, "tcp"); err != nil {
			t.Fatalf("unexpected ClosePort error: %v", err)
		}

		// Ensure that the delete command executed targeted handle 13 specifically
		foundTargetHandle := false
		for _, execCmd := range runner.executed {
			cmdStr := strings.Join(execCmd, " ")
			if strings.HasPrefix(cmdStr, "nft delete rule inet filter input handle") {
				if cmdStr == "nft delete rule inet filter input handle 13" {
					foundTargetHandle = true
				} else {
					t.Fatalf("unexpected handle deletion: %s (should have matched only handle 13 for port 80)", cmdStr)
				}
			}
		}
		if !foundTargetHandle {
			t.Fatalf("expected handle 13 to be deleted for port 80, but was not executed: %v", runner.executed)
		}
	})

	t.Run("successfully opens and closes port on IPTables", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["iptables"] = "/sbin/iptables"

		mgr := firewall.NewManagerWithRunner(runner)
		if err := mgr.OpenPort(8443, "tcp", "Fabric Server"); err != nil {
			t.Fatalf("unexpected open error: %v", err)
		}
		if err := mgr.ClosePort(8443, "tcp"); err != nil {
			t.Fatalf("unexpected close error: %v", err)
		}
	})

	t.Run("noop when no firewall detected", func(t *testing.T) {
		runner := newMockRunner()
		mgr := firewall.NewManagerWithRunner(runner)
		if err := mgr.OpenPort(8443, "tcp", "Fabric Server"); err != nil {
			t.Fatalf("expected nil on no firewall, got %v", err)
		}
		if err := mgr.ClosePort(8443, "tcp"); err != nil {
			t.Fatalf("expected nil on no firewall, got %v", err)
		}
	})

	t.Run("returns descriptive error on Firewalld permission failure", func(t *testing.T) {
		runner := newMockRunner()
		runner.lookPathMap["firewall-cmd"] = "/usr/bin/firewall-cmd"
		runner.runOutputs["firewall-cmd --state"] = mockRunResult{output: []byte("running\n"), err: nil}
		runner.runOutputs["firewall-cmd --permanent --add-port=8443/tcp"] = mockRunResult{
			output: []byte("Authorization failed\n"),
			err:    errors.New("exit status 1"),
		}

		mgr := firewall.NewManagerWithRunner(runner)
		err := mgr.OpenPort(8443, "tcp", "Fabric Server")
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		var permErr *firewall.PermissionError
		if !errors.As(err, &permErr) {
			t.Fatalf("expected PermissionError, got %T (%v)", err, err)
		}
	})

	t.Run("creates default host manager without panic", func(t *testing.T) {
		mgr := firewall.NewManager()
		if mgr == nil {
			t.Fatal("expected non-nil manager")
		}
	})
}
