package cli

import (
	"errors"
	"fmt"
	"net"
	"strings"
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
			return fmt.Sprintf("Error: Connection refused (%s)\n  👉 Tip: Unable to reach Fabric server. Check if fabric-server is active ('fabric thread service status') or verify '--server'.", addr)
		}
		return fmt.Sprintf("Error: Connection refused\n  👉 Tip: Unable to reach Fabric server. Check if fabric-server is active ('fabric thread service status') or verify '--server'.")
	}

	return fmt.Sprintf("Error: %v", err)
}
