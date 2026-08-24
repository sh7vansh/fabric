package service

import (
	"strings"
	"testing"
)

func TestGenerateSystemdSystemUnit(t *testing.T) {
	mgr := NewInitManager()
	unit := mgr.GenerateSystemdSystemUnit("node", "/usr/local/bin/fabric-node")

	if !strings.Contains(unit, "Description=Fabric Mesh Network Node") {
		t.Errorf("missing description in system unit: %s", unit)
	}
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/fabric-node") {
		t.Errorf("missing ExecStart in system unit: %s", unit)
	}
	if !strings.Contains(unit, "ExecStopPost=/usr/bin/resolvectl revert lo") {
		t.Errorf("missing ExecStopPost in node system unit: %s", unit)
	}
}

func TestGenerateSystemdUserUnit(t *testing.T) {
	mgr := NewInitManager()
	unit := mgr.GenerateSystemdUserUnit("socket", "/home/user/.local/bin/fabric-socket", "/home/user/.config/fabric/socket.env")

	if !strings.Contains(unit, "Description=Fabric Mesh Network Socket (User)") {
		t.Errorf("missing description in user unit: %s", unit)
	}
	if !strings.Contains(unit, "EnvironmentFile=-/home/user/.config/fabric/socket.env") {
		t.Errorf("missing environment file in user unit: %s", unit)
	}
	if !strings.Contains(unit, "ExecStart=/home/user/.local/bin/fabric-socket") {
		t.Errorf("missing ExecStart in user unit: %s", unit)
	}
}

func TestGenerateSupervisorScript(t *testing.T) {
	mgr := NewInitManager()
	script := mgr.GenerateSupervisorScript("/tmp/node.pid", "/tmp/node.env", "/usr/bin/fabric-node")

	if !strings.Contains(script, `PIDFILE="/tmp/node.pid"`) {
		t.Errorf("missing pidfile in supervisor script: %s", script)
	}
	if !strings.Contains(script, `ENVFILE="/tmp/node.env"`) {
		t.Errorf("missing envfile in supervisor script: %s", script)
	}
	if !strings.Contains(script, `BIN="/usr/bin/fabric-node"`) {
		t.Errorf("missing bin in supervisor script: %s", script)
	}
}

func TestRenderBootstrapScript(t *testing.T) {
	mgr := NewInitManager()
	opts := BootstrapScriptOptions{
		SocketURL:   "ws://10.0.0.1:8080/ws",
		ListenAddr:  ":8443",
		Token:       "tok-123",
		Domain:      "custom.mesh",
		Tags:        []string{"ingress", "edge"},
		NodePayload: "base64-node-payload",
		CliPayload:  "base64-cli-payload",
		CAPayload:   "base64-ca-cert",
		CertPayload: "base64-node-cert",
		KeyPayload:  "base64-node-key",
	}

	script := mgr.RenderBootstrapScript(opts)

	if !strings.Contains(script, "FABRIC_SOCKET_URL=ws://10.0.0.1:8080/ws") {
		t.Errorf("missing socket url in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "FABRIC_LISTEN=:8443") {
		t.Errorf("missing listen addr in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "FABRIC_TOKEN=tok-123") {
		t.Errorf("missing token in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "FABRIC_DOMAIN=custom.mesh") {
		t.Errorf("missing domain in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "FABRIC_TAGS=ingress,edge") {
		t.Errorf("missing tags in bootstrap script: %s", script)
	}
	if !strings.Contains(script, `PAYLOAD="base64-node-payload"`) {
		t.Errorf("missing node payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, `CLI_PAYLOAD="base64-cli-payload"`) {
		t.Errorf("missing cli payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, `CA_PAYLOAD="base64-ca-cert"`) {
		t.Errorf("missing ca payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, `CERT_PAYLOAD="base64-node-cert"`) {
		t.Errorf("missing cert payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, `KEY_PAYLOAD="base64-node-key"`) {
		t.Errorf("missing key payload in bootstrap script: %s", script)
	}
	if !strings.Contains(script, "chmod 600") {
		t.Errorf("missing 0600 permission for private key in bootstrap script: %s", script)
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
	if !strings.Contains(script, "systemctl restart fabric-node") {
		t.Errorf("missing systemctl restart in switch script: %s", script)
	}
}

