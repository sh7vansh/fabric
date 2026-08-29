package service

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// BootstrapRenderer is a pure template rendering engine for Fabric bootstrap scripts.
type BootstrapRenderer struct{}

// NewBootstrapRenderer creates a new pure BootstrapRenderer.
func NewBootstrapRenderer() *BootstrapRenderer {
	return &BootstrapRenderer{}
}

// RenderBootstrapScript renders the canonical air-gapped bootstrap shell script for remote stitching.
func (r *BootstrapRenderer) RenderBootstrapScript(opts BootstrapScriptOptions) string {
	tagsJoined := strings.Join(opts.Tags, ",")

	serverURL := opts.ServerURL
	if serverURL == "" {
		serverURL = opts.SocketURL
	}
	mode := opts.Mode
	if mode == "inverted" {
		mode = "remote"
	} else if mode == "normal" {
		mode = "local"
	}
	if mode == "" {
		if opts.ListenAddr != "" {
			mode = "remote"
		} else {
			mode = "local"
		}
	}

	threadPayload := opts.ThreadPayload
	if threadPayload == "" {
		threadPayload = opts.NodePayload
	}

	threadName := opts.ThreadName
	if threadName == "" {
		threadName = opts.NodeName
	}

	var envBuilder strings.Builder
	envBuilder.WriteString(fmt.Sprintf("FABRIC_SERVER_URL=%s\n", serverURL))
	envBuilder.WriteString(fmt.Sprintf("FABRIC_SOCKET_URL=%s\n", serverURL))
	if threadName != "" {
		envBuilder.WriteString(fmt.Sprintf("FABRIC_THREAD_NAME=%s\n", threadName))
		envBuilder.WriteString(fmt.Sprintf("FABRIC_NODE_NAME=%s\n", threadName))
	}
	envBuilder.WriteString(fmt.Sprintf("FABRIC_MODE=%s\n", mode))
	envBuilder.WriteString(fmt.Sprintf("FABRIC_LISTEN=%s\n", opts.ListenAddr))
	envBuilder.WriteString(fmt.Sprintf("FABRIC_TOKEN=%s\n", opts.Token))
	envBuilder.WriteString(fmt.Sprintf("FABRIC_DOMAIN=%s\n", opts.Domain))
	envBuilder.WriteString(fmt.Sprintf("FABRIC_TAGS=%s\n", tagsJoined))
	rawEnv := envBuilder.String()
	envB64 := base64.StdEncoding.EncodeToString([]byte(rawEnv))

	return fmt.Sprintf(`#!/usr/bin/env bash
set -e

echo "[+] Initializing Fabric air-gapped zero-internet bootstrap..."

# 1. Privilege Level Detection
IS_ROOT=0
SUDO=""
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=1
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    IS_ROOT=1
    SUDO="sudo"
fi

# 2. Systemd Capability Detection
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=1
fi

# 3. Determine Installation Paths
if [ "$IS_ROOT" -eq 1 ]; then
    INSTALL_BIN_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/fabric"
    RUN_DIR="/var/run/fabric"
    $SUDO mkdir -p "$INSTALL_BIN_DIR" "$CONFIG_DIR" "$RUN_DIR"
else
    INSTALL_BIN_DIR="$HOME/.local/bin"
    CONFIG_DIR="$HOME/.config/fabric"
    RUN_DIR="$HOME/.fabric"
    mkdir -p "$INSTALL_BIN_DIR" "$CONFIG_DIR" "$RUN_DIR"
fi

TARGET_BIN="$INSTALL_BIN_DIR/fabric-thread"
ENV_FILE="$CONFIG_DIR/thread.env"

# 4. Extract Injected Self-Contained Binary Payload
if [ -n "%s" ]; then
    echo "[+] Unpacking injected fabric-thread binary to $TARGET_BIN..."
    TMP_BIN="${TARGET_BIN}.tmp.$$"
    unpack_thread() {
        base64 -d << 'THREAD_PAYLOAD_EOF' | gzip -d
%s
THREAD_PAYLOAD_EOF
    }
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        unpack_thread | $SUDO tee "$TMP_BIN" > /dev/null
        $SUDO chmod 755 "$TMP_BIN"
        $SUDO mv -f "$TMP_BIN" "$TARGET_BIN"
    else
        unpack_thread > "$TMP_BIN"
        chmod 755 "$TMP_BIN"
        mv -f "$TMP_BIN" "$TARGET_BIN"
    fi
fi

# Extract CLI binary if available
if [ -n "%s" ]; then
    echo "[+] Unpacking injected fabric CLI to $INSTALL_BIN_DIR/fabric..."
    TARGET_CLI="$INSTALL_BIN_DIR/fabric"
    TMP_CLI="${TARGET_CLI}.tmp.$$"
    unpack_cli() {
        base64 -d << 'CLI_PAYLOAD_EOF' | gzip -d
%s
CLI_PAYLOAD_EOF
    }
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        unpack_cli | $SUDO tee "$TMP_CLI" > /dev/null
        $SUDO chmod 755 "$TMP_CLI"
        $SUDO mv -f "$TMP_CLI" "$TARGET_CLI"
    else
        unpack_cli > "$TMP_CLI"
        chmod 755 "$TMP_CLI"
        mv -f "$TMP_CLI" "$TARGET_CLI"
    fi
fi

# Validate binary integrity and executable permissions
if [ ! -s "$TARGET_BIN" ] || [ ! -x "$TARGET_BIN" ]; then
    if command -v fabric-thread >/dev/null 2>&1; then
        TARGET_BIN="$(command -v fabric-thread)"
    elif [ -x "/usr/local/bin/fabric-thread" ]; then
        TARGET_BIN="/usr/local/bin/fabric-thread"
    elif command -v fabric-node >/dev/null 2>&1; then
        TARGET_BIN="$(command -v fabric-node)"
    elif [ -x "/usr/local/bin/fabric-node" ]; then
        TARGET_BIN="/usr/local/bin/fabric-node"
    else
        echo "[!] Binary validation failed: $TARGET_BIN not found or not executable" >&2
        exit 1
    fi
fi
echo "[+] Validated binary integrity: $TARGET_BIN"

# 5. Extract Injected mTLS PKI Payloads
if [ -n "%s" ]; then
    echo "[+] Unpacking Root CA certificate to $CONFIG_DIR/ca.crt..."
    unpack_ca() {
        base64 -d << 'CA_EOF'
%s
CA_EOF
    }
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        unpack_ca | $SUDO tee "$CONFIG_DIR/ca.crt" > /dev/null
        $SUDO chmod 644 "$CONFIG_DIR/ca.crt"
    else
        unpack_ca > "$CONFIG_DIR/ca.crt"
        chmod 644 "$CONFIG_DIR/ca.crt"
    fi
fi

if [ -n "%s" ]; then
    echo "[+] Unpacking thread leaf certificate to $CONFIG_DIR/client.crt..."
    unpack_cert() {
        base64 -d << 'CERT_EOF'
%s
CERT_EOF
    }
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        unpack_cert | $SUDO tee "$CONFIG_DIR/client.crt" > /dev/null
        $SUDO chmod 644 "$CONFIG_DIR/client.crt"
    else
        unpack_cert > "$CONFIG_DIR/client.crt"
        chmod 644 "$CONFIG_DIR/client.crt"
    fi
fi

if [ -n "%s" ]; then
    echo "[+] Unpacking thread leaf private key to $CONFIG_DIR/client.key..."
    unpack_key() {
        base64 -d << 'KEY_EOF'
%s
KEY_EOF
    }
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        unpack_key | $SUDO tee "$CONFIG_DIR/client.key" > /dev/null
        $SUDO chmod 600 "$CONFIG_DIR/client.key"
    else
        unpack_key > "$CONFIG_DIR/client.key"
        chmod 600 "$CONFIG_DIR/client.key"
    fi
fi

# 6. Write Environment Configuration
unpack_env() {
    base64 -d << 'ENV_EOF'
%s
ENV_EOF
}
if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
    unpack_env | $SUDO tee "$ENV_FILE" > /dev/null
    $SUDO chmod 600 "$ENV_FILE"
    # Legacy fallback link
    $SUDO cp -f "$ENV_FILE" "$CONFIG_DIR/node.env" 2>/dev/null || true
else
    unpack_env > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    cp -f "$ENV_FILE" "$CONFIG_DIR/node.env" 2>/dev/null || true
fi

# 7. Multi-Tier Init Selection & Service Activation
if [ "$IS_ROOT" -eq 1 ] && [ "$HAS_SYSTEMD" -eq 1 ]; then
    # Disable any legacy units
    $SUDO systemctl stop fabric-node fabric-agent 2>/dev/null || true
    $SUDO systemctl disable fabric-node fabric-agent 2>/dev/null || true
    $SUDO rm -f /etc/systemd/system/fabric-node.service /etc/systemd/system/fabric-agent.service

    # Tier 1: Root / Sudo with systemd (System service)
    echo "[+] Configuring systemd system service (/etc/systemd/system/fabric-thread.service)..."
    cat << 'UNIT_EOF' | $SUDO tee /etc/systemd/system/fabric-thread.service > /dev/null
[Unit]
Description=Fabric Mesh Network Thread
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=HOME=/root
EnvironmentFile=-/etc/fabric/thread.env
ExecStart=/usr/local/bin/fabric-thread
Restart=always
RestartSec=3s
LimitNOFILE=65536
ExecStopPost=-/usr/bin/resolvectl revert lo

[Install]
WantedBy=multi-user.target
UNIT_EOF

    $SUDO chmod 644 /etc/systemd/system/fabric-thread.service
    $SUDO systemctl daemon-reload
    $SUDO systemctl restart fabric-thread || true
    $SUDO systemctl enable fabric-thread || true
    echo "[+] Systemd system service enabled and active."

elif [ "$IS_ROOT" -eq 0 ] && [ "$HAS_SYSTEMD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    # Tier 2: Non-root with systemd (User service)
    systemctl --user stop fabric-node fabric-agent 2>/dev/null || true
    systemctl --user disable fabric-node fabric-agent 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/fabric-node.service" "$HOME/.config/systemd/user/fabric-agent.service"

    echo "[+] Configuring systemd user service (~/.config/systemd/user/fabric-thread.service)..."
    mkdir -p "$HOME/.config/systemd/user"
    cat << UNIT_EOF > "$HOME/.config/systemd/user/fabric-thread.service"
[Unit]
Description=Fabric Mesh Network Thread (User)
After=network.target

[Service]
Type=simple
EnvironmentFile=-$HOME/.config/fabric/thread.env
ExecStart=$TARGET_BIN
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=default.target
UNIT_EOF

    chmod 644 "$HOME/.config/systemd/user/fabric-thread.service"
    loginctl enable-linger "$(whoami)" 2>/dev/null || true
    systemctl --user daemon-reload || true
    systemctl --user restart fabric-thread || true
    systemctl --user enable fabric-thread || true
    echo "[+] Systemd user service enabled and active."

else
    # Tier 3: Non-systemd / Edge / Container (Supervised background daemon)
    echo "[+] Configuring standalone supervisor daemon in $RUN_DIR..."
    PIDFILE="$RUN_DIR/fabric-thread.pid"
    SUPERVISOR="$RUN_DIR/fabric-thread-supervisor.sh"

    if [ -f "$PIDFILE" ]; then
        OLD_PID=$(cat "$PIDFILE" 2>/dev/null || true)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            kill "$OLD_PID" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$PIDFILE"
    fi

    cat << 'SUPERVISOR_EOF' > "$SUPERVISOR"
` + r.GenerateSupervisorScript("$PIDFILE", "$ENV_FILE", "$TARGET_BIN") + `SUPERVISOR_EOF

    chmod 755 "$SUPERVISOR"
    nohup "$SUPERVISOR" > /dev/null 2>&1 &
    echo $! > "$RUN_DIR/fabric-thread-supervisor.pid"
    echo "[+] Supervised background daemon started (PID file: $PIDFILE)."
fi

# 8. Firewall Configuration (Remote Listening Mode)
if [ "%s" = "remote" ]; then
    PORT_NUM="%s"
    PORT_NUM="${PORT_NUM#:}"
    [ -z "$PORT_NUM" ] && PORT_NUM="8443"
    echo "[+] Configuring firewall for remote listening port ($PORT_NUM/tcp)..."
    if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -qi "status: active"; then
        $SUDO ufw allow "$PORT_NUM/tcp" comment "Fabric Remote Thread Listener" 2>/dev/null || $SUDO ufw allow "$PORT_NUM/tcp" || true
        echo "[+] Configured ufw rule for port $PORT_NUM/tcp"
    elif command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state 2>/dev/null | grep -qi "running"; then
        $SUDO firewall-cmd --permanent --add-port="$PORT_NUM/tcp" 2>/dev/null && $SUDO firewall-cmd --reload 2>/dev/null || true
        echo "[+] Configured firewalld rule for port $PORT_NUM/tcp"
    elif command -v nft >/dev/null 2>&1; then
        $SUDO nft add rule inet filter input tcp dport "$PORT_NUM" accept comment "Fabric Remote Thread Listener" 2>/dev/null || $SUDO nft add rule inet filter input tcp dport "$PORT_NUM" accept 2>/dev/null || true
        echo "[+] Configured nftables rule for port $PORT_NUM/tcp"
    elif command -v iptables >/dev/null 2>&1; then
        $SUDO iptables -I INPUT -p tcp --dport "$PORT_NUM" -m comment --comment "Fabric Remote Thread Listener" -j ACCEPT 2>/dev/null || $SUDO iptables -I INPUT -p tcp --dport "$PORT_NUM" -j ACCEPT 2>/dev/null || true
        echo "[+] Configured iptables rule for port $PORT_NUM/tcp"
    fi
fi
`, threadPayload, threadPayload, opts.CliPayload, opts.CliPayload, opts.CAPayload, opts.CAPayload, opts.CertPayload, opts.CertPayload, opts.KeyPayload, opts.KeyPayload, envB64, mode, opts.ListenAddr)
}

// RenderRemoteSwitchScript renders a lightweight SSH command to switch an existing thread to remote mode.
func (r *BootstrapRenderer) RenderRemoteSwitchScript(listenPort string) string {
	if !strings.HasPrefix(listenPort, ":") {
		listenPort = ":" + listenPort
	}
	portNum := strings.TrimPrefix(listenPort, ":")
	if portNum == "" {
		portNum = "8443"
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -e

PORT="%s"

# Locate environment file
ENV_FILE="/etc/fabric/thread.env"
if [ ! -f "$ENV_FILE" ] && [ -f "$HOME/.config/fabric/thread.env" ]; then
    ENV_FILE="$HOME/.config/fabric/thread.env"
elif [ ! -f "$ENV_FILE" ] && [ -f "/etc/fabric/node.env" ]; then
    ENV_FILE="/etc/fabric/node.env"
elif [ ! -f "$ENV_FILE" ] && [ -f "$HOME/.config/fabric/node.env" ]; then
    ENV_FILE="$HOME/.config/fabric/node.env"
fi

if [ -f "$ENV_FILE" ]; then
    if grep -q "FABRIC_LISTEN=" "$ENV_FILE" 2>/dev/null; then
        if [ "$EUID" -eq 0 ]; then
            sed -i "s|^FABRIC_LISTEN=.*|FABRIC_LISTEN=$PORT|" "$ENV_FILE"
            sed -i "s|^FABRIC_MODE=.*|FABRIC_MODE=remote|" "$ENV_FILE" 2>/dev/null || true
        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo sed -i "s|^FABRIC_LISTEN=.*|FABRIC_LISTEN=$PORT|" "$ENV_FILE"
            sudo sed -i "s|^FABRIC_MODE=.*|FABRIC_MODE=remote|" "$ENV_FILE" 2>/dev/null || true
        else
            sed -i "s|^FABRIC_LISTEN=.*|FABRIC_LISTEN=$PORT|" "$ENV_FILE"
            sed -i "s|^FABRIC_MODE=.*|FABRIC_MODE=remote|" "$ENV_FILE" 2>/dev/null || true
        fi
    else
        if [ "$EUID" -eq 0 ]; then
            echo "FABRIC_MODE=remote" >> "$ENV_FILE"
            echo "FABRIC_LISTEN=$PORT" >> "$ENV_FILE"
        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo sh -c "echo 'FABRIC_MODE=remote' >> $ENV_FILE"
            sudo sh -c "echo 'FABRIC_LISTEN=$PORT' >> $ENV_FILE"
        else
            echo "FABRIC_MODE=remote" >> "$ENV_FILE"
            echo "FABRIC_LISTEN=$PORT" >> "$ENV_FILE"
        fi
    fi
fi

# Configure firewall for remote port
PORT_NUM="%s"
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -qi "status: active"; then
    sudo ufw allow "$PORT_NUM/tcp" comment "Fabric Remote Thread Listener" 2>/dev/null || sudo ufw allow "$PORT_NUM/tcp" || true
elif command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --state 2>/dev/null | grep -qi "running"; then
    sudo firewall-cmd --permanent --add-port="$PORT_NUM/tcp" 2>/dev/null && sudo firewall-cmd --reload 2>/dev/null || true
elif command -v nft >/dev/null 2>&1; then
    sudo nft add rule inet filter input tcp dport "$PORT_NUM" accept comment "Fabric Remote Thread Listener" 2>/dev/null || sudo nft add rule inet filter input tcp dport "$PORT_NUM" accept 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    sudo iptables -I INPUT -p tcp --dport "$PORT_NUM" -m comment --comment "Fabric Remote Thread Listener" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport "$PORT_NUM" -j ACCEPT 2>/dev/null || true
fi

# Restart service
if [ "$EUID" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl restart fabric-thread 2>/dev/null || systemctl restart fabric-node 2>/dev/null || true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && command -v systemctl >/dev/null 2>&1; then
    sudo systemctl restart fabric-thread 2>/dev/null || sudo systemctl restart fabric-node 2>/dev/null || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl --user restart fabric-thread 2>/dev/null || systemctl --user restart fabric-node 2>/dev/null || true
fi
`, listenPort, portNum)
}

// RenderInvertedSwitchScript is a backward-compatible alias for RenderRemoteSwitchScript.
func (r *BootstrapRenderer) RenderInvertedSwitchScript(listenPort string) string {
	return r.RenderRemoteSwitchScript(listenPort)
}

// GenerateSupervisorScript renders the standalone background supervisor shell script.
func (r *BootstrapRenderer) GenerateSupervisorScript(pidFile, envFile, binPath string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
PIDFILE="%s"
ENVFILE="%s"
BIN="%s"

cleanup() {
    if [ -n "$CHILD_PID" ]; then
        kill "$CHILD_PID" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

if [ -f "$ENVFILE" ]; then
    set -a
    . "$ENVFILE"
    set +a
fi

while true; do
    "$BIN" &
    CHILD_PID=$!
    echo "$CHILD_PID" > "$PIDFILE"
    wait "$CHILD_PID"
    sleep 2
done
`, pidFile, envFile, binPath)
}
