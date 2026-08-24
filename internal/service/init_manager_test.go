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
		Token:       "tok-123",
		Domain:      "custom.mesh",
		Tags:        []string{"ingress", "edge"},
		NodePayload: "base64-node-payload",
		CliPayload:  "base64-cli-payload",
	}

	script := mgr.RenderBootstrapScript(opts)

	if !strings.Contains(script, "FABRIC_SOCKET_URL=ws://10.0.0.1:8080/ws") {
		t.Errorf("missing socket url in bootstrap script: %s", script)
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
}
