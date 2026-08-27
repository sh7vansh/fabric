package thread

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fabric/internal/protocol"
)

func quoteShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func (s *NativeSandbox) formatEnvExports(env []string) string {
	sanitized := s.SanitizeEnv(env)
	var envPrefix strings.Builder
	for _, e := range sanitized {
		parts := strings.SplitN(e, "=", 2)
		key := parts[0]
		if len(parts) == 2 {
			envPrefix.WriteString(fmt.Sprintf("export %s=%s\n", key, quoteShellArg(parts[1])))
		} else {
			envPrefix.WriteString(fmt.Sprintf("export %s\n", key))
		}
	}
	return envPrefix.String()
}

var validEnvKeyRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
var validUsernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

var defaultBlockedEnvKeys = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"LD_AUDIT":              true,
	"PYTHONPATH":            true,
	"PYTHONHOME":            true,
	"PERL5OPT":              true,
	"PERLLIB":               true,
	"PERL5LIB":              true,
	"RUBYOPT":               true,
	"RUBYLIB":               true,
	"NODE_OPTIONS":          true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"PROMPT_COMMAND":        true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_INSERT_LIBRARIES": true,
	"IFS":                   true,
}

// ExecutionSandbox defines the contract for command sandboxing, credential dropping,
// environment sanitization, and process group lifecycle control.
type ExecutionSandbox interface {
	PrepareCmd(req protocol.ExecRequest) (*exec.Cmd, error)
	SanitizeEnv(env []string) []string
	KillProcessGroup(pid int) error
}

// SandboxConfig configures execution sandboxing.
type SandboxConfig struct {
	DefaultUser    string
	DefaultGroup   string
	DropPrivileges bool
	BlockedEnv     map[string]bool
}

// NativeSandbox is the default POSIX implementation of ExecutionSandbox.
type NativeSandbox struct {
	cfg        SandboxConfig
	blockedEnv map[string]bool
}

// NewExecutionSandbox creates a new NativeSandbox.
func NewExecutionSandbox(cfg SandboxConfig) *NativeSandbox {
	blocked := make(map[string]bool)
	for k, v := range defaultBlockedEnvKeys {
		blocked[k] = v
	}
	for k, v := range cfg.BlockedEnv {
		blocked[k] = v
	}

	return &NativeSandbox{
		cfg:        cfg,
		blockedEnv: blocked,
	}
}

// SanitizeEnv filters and validates environment variables against injection attacks and poisoned keys.
func (s *NativeSandbox) SanitizeEnv(env []string) []string {
	var clean []string
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		key := strings.TrimSpace(parts[0])
		if !validEnvKeyRegex.MatchString(key) {
			continue
		}
		if s.blockedEnv[strings.ToUpper(key)] {
			continue
		}
		if len(parts) == 2 {
			clean = append(clean, fmt.Sprintf("%s=%s", key, parts[1]))
		} else {
			clean = append(clean, key)
		}
	}
	return clean
}

// PrepareCmd prepares an exec.Cmd configured with POSIX credential dropping,
// environment sanitization, and process group isolation.
func (s *NativeSandbox) PrepareCmd(req protocol.ExecRequest) (*exec.Cmd, error) {
	targetUser := req.User
	if targetUser == "" {
		targetUser = s.cfg.DefaultUser
	}

	var cmd *exec.Cmd

	if targetUser != "" {
		if !validUsernameRegex.MatchString(targetUser) {
			return nil, fmt.Errorf("invalid username %q", targetUser)
		}

		// Try native credential drop if running as superuser on linux/darwin
		if os.Geteuid() == 0 && runtime.GOOS != "windows" {
			u, err := user.Lookup(targetUser)
			if err == nil {
				uid, errU := strconv.ParseUint(u.Uid, 10, 32)
				gid, errG := strconv.ParseUint(u.Gid, 10, 32)
				if errU == nil && errG == nil {
					cmd = exec.Command("sh", "-c", req.Command)
					cmd.SysProcAttr = &syscall.SysProcAttr{
						Setpgid: true,
						Credential: &syscall.Credential{
							Uid: uint32(uid),
							Gid: uint32(gid),
						},
					}
					if u.HomeDir != "" && req.WorkDir == "" {
						cmd.Dir = u.HomeDir
					}
				}
			}
		}

		if cmd == nil {
			envPrefix := s.formatEnvExports(req.Env)
			fullCmd := envPrefix + req.Command
			cmd = exec.Command("su", "-", targetUser, "-c", fullCmd)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		}
	} else {
		cmd = exec.Command("sh", "-c", req.Command)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}

	sanitizedEnv := s.SanitizeEnv(req.Env)
	if len(sanitizedEnv) > 0 {
		cmd.Env = append(os.Environ(), sanitizedEnv...)
	}

	return cmd, nil
}

// KillProcessGroup terminates a process group with SIGTERM, falling back to SIGKILL.
func (s *NativeSandbox) KillProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}

	targetPGID := pid
	if pgid, err := syscall.Getpgid(pid); err == nil {
		targetPGID = pgid
	}

	// Send SIGTERM to entire process group
	_ = syscall.Kill(-targetPGID, syscall.SIGTERM)

	// Monitor if entire process group exits within 500ms grace period; if not, enforce SIGKILL
	terminated := false
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := syscall.Kill(-targetPGID, 0); err != nil {
			terminated = true
			break
		}
	}

	if !terminated {
		// Enforce SIGKILL on the stubborn process group
		_ = syscall.Kill(-targetPGID, syscall.SIGKILL)
		for i := 0; i < 10; i++ {
			time.Sleep(20 * time.Millisecond)
			if err := syscall.Kill(-targetPGID, 0); err != nil {
				break
			}
		}
	}

	return nil
}

var defaultSandbox = NewExecutionSandbox(SandboxConfig{})

// SanitizeEnv filters environment variables using the default sandbox rules.
func SanitizeEnv(env []string) []string {
	return defaultSandbox.SanitizeEnv(env)
}

// formatEnvExports formats shell export statements using the default sandbox rules.
func formatEnvExports(env []string) string {
	return defaultSandbox.formatEnvExports(env)
}

// KillProcessGroup kills a process group using the default sandbox.
func KillProcessGroup(pid int) error {
	return defaultSandbox.KillProcessGroup(pid)
}
