package thread_test

import (
	"runtime"
	"syscall"
	"testing"
	"time"

	"fabric/internal/protocol"
	"fabric/internal/thread"
)

func TestExecutionSandbox_SanitizeEnv(t *testing.T) {
	sandbox := thread.NewExecutionSandbox(thread.SandboxConfig{
		BlockedEnv: map[string]bool{
			"CUSTOM_BLOCKED": true,
		},
	})

	input := []string{
		"VALID_VAR=hello",
		"LD_PRELOAD=/tmp/evil.so",
		"PYTHONPATH=/tmp/lib",
		"NODE_OPTIONS=--inspect",
		"PERL5OPT=-Mevil",
		"RUBYOPT=-revi",
		"BASH_ENV=/tmp/pwn",
		"CUSTOM_BLOCKED=forbidden",
		"INVALID-KEY=val",
		"VALID_KEY2=val2",
	}

	sanitized := sandbox.SanitizeEnv(input)

	sanitizedMap := make(map[string]bool)
	for _, s := range sanitized {
		sanitizedMap[s] = true
	}

	if !sanitizedMap["VALID_VAR=hello"] {
		t.Errorf("expected VALID_VAR=hello to be preserved")
	}
	if !sanitizedMap["VALID_KEY2=val2"] {
		t.Errorf("expected VALID_KEY2=val2 to be preserved")
	}
	if sanitizedMap["LD_PRELOAD=/tmp/evil.so"] {
		t.Errorf("expected LD_PRELOAD to be blocked")
	}
	if sanitizedMap["PYTHONPATH=/tmp/lib"] {
		t.Errorf("expected PYTHONPATH to be blocked")
	}
	if sanitizedMap["NODE_OPTIONS=--inspect"] {
		t.Errorf("expected NODE_OPTIONS to be blocked")
	}
	if sanitizedMap["CUSTOM_BLOCKED=forbidden"] {
		t.Errorf("expected CUSTOM_BLOCKED to be blocked")
	}
	if sanitizedMap["INVALID-KEY=val"] {
		t.Errorf("expected invalid syntax key to be filtered out")
	}
}

func TestExecutionSandbox_PrepareCmd_ProcessGroupIsolation(t *testing.T) {
	sandbox := thread.NewExecutionSandbox(thread.SandboxConfig{})

	req := protocol.ExecRequest{
		Command: "echo 'hello'",
		Env:     []string{"TEST_VAR=123", "LD_PRELOAD=/evil.so"},
		WorkDir: "/tmp",
	}

	cmd, err := sandbox.PrepareCmd(req)
	if err != nil {
		t.Fatalf("PrepareCmd failed: %v", err)
	}

	if cmd.Dir != "/tmp" {
		t.Errorf("expected dir /tmp, got %s", cmd.Dir)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Errorf("expected SysProcAttr.Setpgid to be true for process group isolation")
	}

	foundTestVar := false
	for _, e := range cmd.Env {
		if e == "TEST_VAR=123" {
			foundTestVar = true
		}
		if e == "LD_PRELOAD=/evil.so" {
			t.Errorf("cmd.Env contains blocked LD_PRELOAD")
		}
	}
	if !foundTestVar {
		t.Errorf("expected TEST_VAR=123 to be present in cmd.Env")
	}
}

func TestExecutionSandbox_KillProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping process group kill test on windows")
	}

	sandbox := thread.NewExecutionSandbox(thread.SandboxConfig{})

	req := protocol.ExecRequest{
		Command: "sleep 30",
	}

	cmd, err := sandbox.PrepareCmd(req)
	if err != nil {
		t.Fatalf("PrepareCmd failed: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start test command: %v", err)
	}

	pid := cmd.Process.Pid
	if pid <= 0 {
		t.Fatalf("Invalid pid: %d", pid)
	}

	// Verify process is running
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("Process is not running: %v", err)
	}

	// Kill process group
	if err := sandbox.KillProcessGroup(pid); err != nil {
		t.Fatalf("KillProcessGroup failed: %v", err)
	}

	_ = cmd.Wait()

	// Wait up to 500ms to verify process is dead
	dead := false
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := syscall.Kill(pid, 0); err != nil {
			dead = true
			break
		}
	}

	if !dead {
		t.Errorf("Process %d is still alive after KillProcessGroup", pid)
	}
}

func TestExecutionSandbox_InvalidUsername(t *testing.T) {
	sandbox := thread.NewExecutionSandbox(thread.SandboxConfig{})

	req := protocol.ExecRequest{
		Command: "whoami",
		User:    "root; rm -rf /",
	}

	_, err := sandbox.PrepareCmd(req)
	if err == nil {
		t.Fatalf("expected error for invalid username with injection attempt, got nil")
	}
}
