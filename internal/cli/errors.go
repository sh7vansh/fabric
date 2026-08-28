package cli

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ExitCodeError represents a process termination with a specific exit code.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

func (e *ExitCodeError) ExitCode() int {
	return e.Code
}

// FormatError provides context-aware, actionable diagnostic guidance for runtime CLI errors.
func FormatError(err error) string {
	if err == nil {
		return ""
	}

	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.Error()
	}

	errStr := err.Error()

	// 1. x509 Unknown Authority
	if strings.Contains(errStr, "certificate signed by unknown authority") ||
		strings.Contains(errStr, "x509: certificate signed by unknown authority") {
		return fmt.Sprintf("Error: %v\n  👉 Tip: The server is using a private Root CA. Run 'fabric init --trust-ca' or pass '--ca-cert /path/to/ca.crt'", err)
	}

	// 2. 401 Unauthorized
	if strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication failed") {
		return fmt.Sprintf("Error: Authentication failed (401 Unauthorized)\n  👉 Tip: Verify cluster token in ~/.fabric/config.json, pass '--token <token>', or set FABRIC_TOKEN.")
	}

	// 3. Connection Refused
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connect: connection refused") {
		var opErr *net.OpError
		addr := ""
		if errors.As(err, &opErr) && opErr.Addr != nil {
			addr = opErr.Addr.String()
		}
		if addr != "" {
			return fmt.Sprintf("Error: Connection refused (%s)\n  👉 Tip: Unable to reach Fabric server. Check if fabric-server is active on the target host or verify '--server'.", addr)
		}
		return fmt.Sprintf("Error: Connection refused\n  👉 Tip: Unable to reach Fabric server. Check if fabric-server is active on the target host or verify '--server'.")
	}

	return fmt.Sprintf("Error: %v", err)
}

// FormatPlatform formats OS and Arch into standard "os/arch" representation.
func FormatPlatform(osName, arch string) string {
	if osName != "" && arch != "" {
		return osName + "/" + arch
	}
	if osName != "" {
		return osName
	}
	if arch != "" {
		return arch
	}
	return "-"
}

// FormatRelativeTime converts a timestamp to a friendly relative duration (e.g. "45s ago", "never").
func FormatRelativeTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		if secs > 0 {
			return fmt.Sprintf("%dm%ds ago", mins, secs)
		}
		return fmt.Sprintf("%dm ago", mins)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		mins := int(d.Minutes()) % 60
		if mins > 0 {
			return fmt.Sprintf("%dh%dm ago", hours, mins)
		}
		return fmt.Sprintf("%dh ago", hours)
	}
	days := int(d.Hours()) / 24
	return fmt.Sprintf("%dd ago", days)
}
