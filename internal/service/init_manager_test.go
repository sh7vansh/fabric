package service

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSystemdSystemUnit(t *testing.T) {
	mgr := NewInitManager()
	unit := mgr.GenerateSystemdSystemUnit("thread", "/usr/local/bin/fabric-thread")

	if !strings.Contains(unit, "Description=Fabric Mesh Network Thread") {
		t.Errorf("missing description in system unit: %s", unit)
	}
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/fabric-thread") {
		t.Errorf("missing ExecStart in system unit: %s", unit)
	}
	if !strings.Contains(unit, "ExecStopPost=-/usr/bin/resolvectl revert lo") {
		t.Errorf("missing ExecStopPost in thread system unit: %s", unit)
	}

	threadUnit := mgr.GenerateSystemdSystemUnit("thread", "/usr/local/bin/fabric-thread")
	if !strings.Contains(threadUnit, "Description=Fabric Mesh Network Thread") {
		t.Errorf("missing description in thread unit: %s", threadUnit)
	}
	if !strings.Contains(threadUnit, "ExecStart=/usr/local/bin/fabric-thread") {
		t.Errorf("missing ExecStart in thread unit: %s", threadUnit)
	}
}

func TestGenerateSystemdUserUnit(t *testing.T) {
	mgr := NewInitManager()
	unit := mgr.GenerateSystemdUserUnit("server", "/home/user/.local/bin/fabric-server", "/home/user/.config/fabric/server.env")

	if !strings.Contains(unit, "Description=Fabric Mesh Network Server (User)") {
		t.Errorf("missing description in user unit: %s", unit)
	}
	if !strings.Contains(unit, "EnvironmentFile=-/home/user/.config/fabric/server.env") {
		t.Errorf("missing environment file in user unit: %s", unit)
	}
	if !strings.Contains(unit, "ExecStart=/home/user/.local/bin/fabric-server") {
		t.Errorf("missing ExecStart in user unit: %s", unit)
	}
}

func TestGenerateSupervisorScript(t *testing.T) {
	mgr := NewInitManager()
	renderer := NewBootstrapRenderer()
	pidFile := "/tmp/thread.pid"
	envFile := "/tmp/thread.env"
	binPath := "/usr/bin/fabric-thread"

	scriptMgr := mgr.GenerateSupervisorScript(pidFile, envFile, binPath)
	scriptRenderer := renderer.GenerateSupervisorScript(pidFile, envFile, binPath)

	if scriptMgr != scriptRenderer {
		t.Fatalf("InitManager and BootstrapRenderer produced divergent supervisor scripts:\nInitManager:\n%s\nBootstrapRenderer:\n%s", scriptMgr, scriptRenderer)
	}

	if !strings.Contains(scriptMgr, `PIDFILE="/tmp/thread.pid"`) {
		t.Errorf("missing pidfile in supervisor script: %s", scriptMgr)
	}
	if !strings.Contains(scriptMgr, `ENVFILE="/tmp/thread.env"`) {
		t.Errorf("missing envfile in supervisor script: %s", scriptMgr)
	}
	if !strings.Contains(scriptMgr, `BIN="/usr/bin/fabric-thread"`) {
		t.Errorf("missing bin in supervisor script: %s", scriptMgr)
	}
	if !strings.Contains(scriptMgr, `echo "$CHILD_PID" > "$PIDFILE"`) {
		t.Errorf("missing child pid tracking in supervisor script: %s", scriptMgr)
	}
	if !strings.Contains(scriptMgr, `trap `) {
		t.Errorf("missing trap handling in supervisor script: %s", scriptMgr)
	}
}

func extractDecodedEnv(script string) string {
	if strings.Contains(script, "ENV_EOF") {
		idxStart := strings.Index(script, "<< 'ENV_EOF'")
		if idxStart != -1 {
			idxStart += len("<< 'ENV_EOF'")
			rem := script[idxStart:]
			idxEnd := strings.Index(rem, "ENV_EOF")
			if idxEnd != -1 {
				b64Data := strings.TrimSpace(rem[:idxEnd])
				if decoded, err := base64.StdEncoding.DecodeString(b64Data); err == nil {
					return string(decoded)
				}
			}
		}
	}
	idxStart := strings.Index(script, `ENV_B64="`)
	if idxStart == -1 {
		return script
	}
	idxStart += len(`ENV_B64="`)
	idxEnd := strings.Index(script[idxStart:], `"`)
	if idxEnd == -1 {
		return script
	}
	b64Data := script[idxStart : idxStart+idxEnd]
	decoded, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return script
	}
	return string(decoded)
}

func TestRenderBootstrapScript_ComprehensiveFlags(t *testing.T) {
	mgr := NewInitManager()
	opts := BootstrapScriptOptions{
		ServerURL:     "wss://10.0.0.1:8443/ws",
		SocketURL:     "wss://10.0.0.1:8443/ws",
		ThreadName:    "worker-prod-1",
		Mode:          "remote",
		ListenAddr:    ":8443",
		Token:         "tok-123",
		Domain:        "custom.mesh",
		Tags:          []string{"ingress", "edge"},
		NodePayload:   "base64-node-payload",
		CliPayload:    "base64-cli-payload",
		CAPayload:     "base64-ca-cert",
		CertPayload:   "base64-node-cert",
		KeyPayload:    "base64-node-key",
	}

	script := mgr.RenderBootstrapScript(opts)

	envStr := extractDecodedEnv(script)

	if !strings.Contains(envStr, "FABRIC_SERVER_URL=wss://10.0.0.1:8443/ws") {
		t.Errorf("missing server url in decoded env: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_THREAD_NAME=worker-prod-1") {
		t.Errorf("missing thread name in decoded env: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_MODE=remote") {
		t.Errorf("missing mode in decoded env: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_LISTEN=:8443") {
		t.Errorf("missing listen addr in decoded env: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_TOKEN=tok-123") {
		t.Errorf("missing token in decoded env: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_DOMAIN=custom.mesh") {
		t.Errorf("missing domain in decoded env: %s", envStr)
	}
	if !strings.Contains(envStr, "FABRIC_TAGS=ingress,edge") {
		t.Errorf("missing tags in decoded env: %s", envStr)
	}
	if !strings.Contains(script, "THREAD_PAYLOAD_EOF") && !strings.Contains(script, `PAYLOAD="base64-node-payload"`) {
		t.Errorf("missing node payload unpacking in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "CA_EOF") && !strings.Contains(script, `CA_PAYLOAD="base64-ca-cert"`) {
		t.Errorf("missing ca payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "CERT_EOF") && !strings.Contains(script, `CERT_PAYLOAD="base64-node-cert"`) {
		t.Errorf("missing cert payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "KEY_EOF") && !strings.Contains(script, `KEY_PAYLOAD="base64-node-key"`) {
		t.Errorf("missing key payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "chmod 600") {
		t.Errorf("missing 0600 permission for private key in bootstrap script: %s", script)
	}
}

func TestRenderBootstrapScript_ShellMetacharactersInjectionSafety(t *testing.T) {
	mgr := NewInitManager()
	opts := BootstrapScriptOptions{
		ServerURL:   "wss://10.0.0.1:8443/ws",
		Token:       `secret" && rm -rf / && echo "pwned; $(whoami); \` + "`id`",
		Domain:      `mesh.local" # comment`,
		Tags:        []string{`tag1"`, `$USER`, "\nMALICIOUS=true"},
		NodePayload: "mock-payload",
	}

	script := mgr.RenderBootstrapScript(opts)

	// Verify the script syntax is safe and doesn't interpolate raw metacharacters into the shell commands
	if strings.Contains(script, `FABRIC_TOKEN=secret" &&`) {
		t.Errorf("script contains unescaped token string injection")
	}

	envStr := extractDecodedEnv(script)

	if !strings.Contains(envStr, opts.Token) {
		t.Errorf("expected decoded env to preserve exact token without corruption")
	}
}

func TestRenderInvertedSwitchScript(t *testing.T) {
	mgr := NewInitManager()
	script := mgr.RenderInvertedSwitchScript("8443")

	if !strings.Contains(script, `PORT=":8443"`) {
		t.Errorf("expected PORT=:8443, got: %s", script)
	}
	if !strings.Contains(script, "FABRIC_LISTEN=") {
		t.Errorf("missing FABRIC_LISTEN update in switch script: %s", script)
	}
	if !strings.Contains(script, "systemctl restart fabric-thread") {
		t.Errorf("missing systemctl restart in switch script: %s", script)
	}
}

func TestRenderRemoteSwitchScript(t *testing.T) {
	mgr := NewInitManager()
	script := mgr.RenderRemoteSwitchScript("8443")

	if !strings.Contains(script, `PORT=":8443"`) {
		t.Errorf("expected PORT=:8443, got: %s", script)
	}
	if !strings.Contains(script, "FABRIC_LISTEN=") {
		t.Errorf("missing FABRIC_LISTEN update in switch script: %s", script)
	}
	if !strings.Contains(script, "systemctl restart fabric-thread") {
		t.Errorf("missing systemctl restart in switch script: %s", script)
	}
}

func TestRenderBootstrapScript_AtomicBinaryUnpack(t *testing.T) {
	mgr := NewInitManager()
	opts := BootstrapScriptOptions{
		ServerURL:   "wss://10.0.0.1:8443/ws",
		NodePayload: "mock-thread-payload",
		CliPayload:  "mock-cli-payload",
	}

	script := mgr.RenderBootstrapScript(opts)

	// Ensure atomic staging for fabric-thread binary
	if !strings.Contains(script, `TMP_BIN="${TARGET_BIN}.tmp.$$"`) && !strings.Contains(script, `TMP_BIN="$TARGET_BIN.tmp"`) {
		t.Errorf("script must use temporary staging path for binary unpacking to avoid ETXTBSY")
	}
	if !strings.Contains(script, `mv -f "$TMP_BIN" "$TARGET_BIN"`) {
		t.Errorf("script must atomically move TMP_BIN over TARGET_BIN")
	}

	// Ensure atomic staging for fabric CLI binary
	if !strings.Contains(script, `TMP_CLI="${TARGET_CLI}.tmp.$$"`) && !strings.Contains(script, `TMP_CLI="$TARGET_CLI.tmp"`) {
		t.Errorf("script must use temporary staging path for CLI binary unpacking to avoid ETXTBSY")
	}
	if !strings.Contains(script, `mv -f "$TMP_CLI" "$TARGET_CLI"`) {
		t.Errorf("script must atomically move TMP_CLI over TARGET_CLI")
	}

	// Ensure no direct in-place piping into TARGET_BIN / TARGET_CLI
	if strings.Contains(script, `tee "$TARGET_BIN"`) || strings.Contains(script, `> "$TARGET_BIN"`) {
		t.Errorf("script must not stream directly into TARGET_BIN (causes ETXTBSY on running binaries)")
	}
	if strings.Contains(script, `tee "$TARGET_CLI"`) || strings.Contains(script, `> "$TARGET_CLI"`) {
		t.Errorf("script must not stream directly into TARGET_CLI (causes ETXTBSY on running binaries)")
	}
}

func TestRenderBootstrapScript_FirewallConfiguration(t *testing.T) {
	mgr := NewInitManager()

	t.Run("remote mode generates multi-backend firewall configuration", func(t *testing.T) {
		opts := BootstrapScriptOptions{
			Mode:       "remote",
			ListenAddr: ":8443",
		}
		script := mgr.RenderBootstrapScript(opts)

		if !strings.Contains(script, `if [ "remote" = "remote" ]; then`) {
			t.Errorf("expected remote mode firewall block, got: %s", script)
		}
		if !strings.Contains(script, "ufw allow") || !strings.Contains(script, "firewall-cmd --permanent --add-port=") ||
			!strings.Contains(script, "nft add rule") || !strings.Contains(script, "iptables -I INPUT") {
			t.Errorf("expected multi-backend firewall commands in remote mode script: %s", script)
		}
	})

	t.Run("local mode does not trigger firewall configuration", func(t *testing.T) {
		opts := BootstrapScriptOptions{
			Mode: "local",
		}
		script := mgr.RenderBootstrapScript(opts)

		if !strings.Contains(script, `if [ "local" = "remote" ]; then`) {
			t.Errorf("expected local mode to not match remote check: %s", script)
		}
	})
}

func TestRenderInvertedSwitchScript_FirewallConfiguration(t *testing.T) {
	mgr := NewInitManager()
	script := mgr.RenderInvertedSwitchScript("8443")

	if !strings.Contains(script, "ufw allow") || !strings.Contains(script, "firewall-cmd --permanent --add-port=") ||
		!strings.Contains(script, "nft add rule") || !strings.Contains(script, "iptables -I INPUT") {
		t.Errorf("expected multi-backend firewall commands in inverted switch script: %s", script)
	}
}

func TestBootstrapRendererPure(t *testing.T) {
	renderer := NewBootstrapRenderer()
	opts := BootstrapScriptOptions{
		ServerURL:     "wss://server.internal:8443/ws",
		ThreadName:    "pure-edge",
		Token:         "pure-tok",
		Domain:        "pure.mesh",
		Tags:          []string{"pure", "test"},
		ThreadPayload: "b64payload",
		CAPayload:     "b64ca",
		CertPayload:   "b64cert",
		KeyPayload:    "b64key",
		ListenAddr:    ":9443",
		Mode:          "remote",
	}

	script := renderer.RenderBootstrapScript(opts)
	envStr := extractDecodedEnv(script)
	if !strings.Contains(envStr, "FABRIC_THREAD_NAME=pure-edge") || !strings.Contains(envStr, "FABRIC_SERVER_URL=wss://server.internal:8443/ws") {
		t.Errorf("expected thread name and server url in decoded env: %s", envStr)
	}
	if !strings.Contains(script, "b64payload") {
		t.Errorf("expected payload in script")
	}
	if !strings.Contains(script, "b64ca") {
		t.Errorf("expected CA payload in script")
	}

	switchScript := renderer.RenderRemoteSwitchScript("9443")
	if !strings.Contains(switchScript, `PORT=":9443"`) {
		t.Errorf("expected PORT=:9443 in switch script, got %s", switchScript)
	}

	supervisor := renderer.GenerateSupervisorScript("/run/test.pid", "/etc/test.env", "/bin/test")
	if !strings.Contains(supervisor, `PIDFILE="/run/test.pid"`) {
		t.Errorf("expected PIDFILE in supervisor script")
	}
}

func TestMemoryServiceAdapterLifecycle(t *testing.T) {
	var mgr ServiceManager = NewMemoryServiceAdapter()

	// 1. Install
	err := mgr.Install("thread", ConfigEnv{"FABRIC_TOKEN": "secret-tok"})
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// 2. Status
	status, err := mgr.Status("thread")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.Active || !status.Running {
		t.Errorf("expected service to be active and running, got %+v", status)
	}

	// 3. Action stop
	if err := mgr.Stop("thread"); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	status, _ = mgr.Status("thread")
	if status.Active {
		t.Errorf("expected stopped service to not be active")
	}

	// 4. Action restart
	if err := mgr.Restart("thread"); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	status, _ = mgr.Status("thread")
	if !status.Active {
		t.Errorf("expected restarted service to be active")
	}

	// 5. Uninstall
	if err := mgr.Uninstall("thread"); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	status, _ = mgr.Status("thread")
	if status.Active {
		t.Errorf("expected uninstalled service to not be active")
	}
}

func TestInitManager_WriteServiceEnv(t *testing.T) {
	mgr := NewInitManager()
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	env := ConfigEnv{
		"FABRIC_SERVER_URL": "wss://test.mesh:8443/ws",
		"FABRIC_TOKEN":      "secret-token-123",
		"FABRIC_MODE":       "remote",
	}

	err := mgr.WriteServiceEnv("thread", env)
	if err != nil {
		t.Fatalf("WriteServiceEnv failed: %v", err)
	}

	targetEnv := filepath.Join(tmpDir, ".fabric", "thread.env")
	data, err := os.ReadFile(targetEnv)
	if err != nil {
		t.Fatalf("failed to read written env file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "FABRIC_SERVER_URL=wss://test.mesh:8443/ws") {
		t.Errorf("missing FABRIC_SERVER_URL in %s", content)
	}
	if !strings.Contains(content, "FABRIC_TOKEN=secret-token-123") {
		t.Errorf("missing FABRIC_TOKEN in %s", content)
	}
	if !strings.Contains(content, "FABRIC_MODE=remote") {
		t.Errorf("missing FABRIC_MODE in %s", content)
	}
}



