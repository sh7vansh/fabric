#!/usr/bin/env bash
set -euo pipefail

# Fabric Mesh Network - Installer Script
# Usage:
#   curl -fsSL https://get.fabric.mesh/install.sh | bash
#   or locally: ./install.sh [--no-setup]

INSTALL_DIR="${FABRIC_INSTALL_DIR:-/usr/local/bin}"
NO_SETUP="${FABRIC_NO_SETUP:-0}"

for arg in "$@"; do
    case "$arg" in
        --no-setup)
            NO_SETUP=1
            ;;
        --dir=*)
            INSTALL_DIR="${arg#*=}"
            ;;
        *)
            ;;
    esac
done

echo "========================================="
echo "   Fabric Mesh Network Installer"
echo "========================================="

# 1. Check OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$OS" != "linux" ]; then
    echo "[-] Error: Fabric currently supports Linux only. Detected OS: $OS"
    exit 1
fi

# 2. Check Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        FABRIC_ARCH="amd64"
        ;;
    aarch64|arm64)
        FABRIC_ARCH="arm64"
        ;;
    armv7l|armhf)
        FABRIC_ARCH="arm"
        ;;
    *)
        echo "[-] Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "[+] Detected Linux ($FABRIC_ARCH)"

# 3. Check Privilege / Target Directory
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
            echo "[+] Using sudo for installation into $INSTALL_DIR"
        else
            INSTALL_DIR="$HOME/.local/bin"
            mkdir -p "$INSTALL_DIR"
            echo "[!] Sudo not found. Installing into user directory: $INSTALL_DIR"
        fi
    fi
fi

$SUDO mkdir -p "$INSTALL_DIR"

# 4. Build or Install Binaries
TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# If running within the fabric source tree, build locally
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
if [ -n "$REPO_DIR" ] && [ -f "$REPO_DIR/go.mod" ] && command -v go >/dev/null 2>&1; then
    echo "[+] Building Fabric binaries from source..."
    (cd "$REPO_DIR" && go build -o "$TMP_DIR/fabric" ./cmd/cli)
    (cd "$REPO_DIR" && go build -o "$TMP_DIR/fabric-socket" ./cmd/socket)
    (cd "$REPO_DIR" && go build -o "$TMP_DIR/fabric-node" ./cmd/node)
else
    # Check if download URL or release is configured
    RELEASE_TAG="${FABRIC_VERSION:-latest}"
    DOWNLOAD_BASE="${FABRIC_DOWNLOAD_URL:-https://github.com/sh7vansh/fabric/releases/download}"
    
    echo "[+] Attempting to download Fabric ($RELEASE_TAG) for linux/$FABRIC_ARCH..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_BASE/$RELEASE_TAG/fabric-linux-$FABRIC_ARCH" -o "$TMP_DIR/fabric" 2>/dev/null || true
        curl -fsSL "$DOWNLOAD_BASE/$RELEASE_TAG/fabric-socket-linux-$FABRIC_ARCH" -o "$TMP_DIR/fabric-socket" 2>/dev/null || true
        curl -fsSL "$DOWNLOAD_BASE/$RELEASE_TAG/fabric-node-linux-$FABRIC_ARCH" -o "$TMP_DIR/fabric-node" 2>/dev/null || true
    fi

    # Fallback to Go build if binaries were not downloaded and Go is available
    if [ ! -f "$TMP_DIR/fabric" ] && command -v go >/dev/null 2>&1; then
        echo "[+] Building Fabric binaries using Go toolchain..."
        GOBIN="$TMP_DIR" go install fabric/cmd/cli@latest 2>/dev/null || true
        GOBIN="$TMP_DIR" go install fabric/cmd/socket@latest 2>/dev/null || true
        GOBIN="$TMP_DIR" go install fabric/cmd/node@latest 2>/dev/null || true
    fi
fi

# Ensure binaries exist
if [ -f "$TMP_DIR/fabric" ]; then
    echo "[+] Installing binaries into $INSTALL_DIR..."
    $SUDO install -m 0755 "$TMP_DIR/fabric" "$INSTALL_DIR/fabric"
    if [ -f "$TMP_DIR/fabric-socket" ]; then
        $SUDO install -m 0755 "$TMP_DIR/fabric-socket" "$INSTALL_DIR/fabric-socket"
    fi
    if [ -f "$TMP_DIR/fabric-node" ]; then
        $SUDO install -m 0755 "$TMP_DIR/fabric-node" "$INSTALL_DIR/fabric-node"
    fi
else
    echo "[-] Error: Binaries could not be compiled or downloaded."
    exit 1
fi

echo "[+] Fabric successfully installed to $INSTALL_DIR/fabric"

# 5. Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "[!] Warning: $INSTALL_DIR is not in your PATH."
    echo "    Add it by running: export PATH=\"\$PATH:$INSTALL_DIR\""
fi

# 6. Handover to Setup
if [ "$NO_SETUP" -eq 0 ]; then
    if [ -t 0 ] && command -v "$INSTALL_DIR/fabric" >/dev/null 2>&1; then
        echo ""
        echo "[+] Launching Fabric setup wizard..."
        "$INSTALL_DIR/fabric" setup || true
    else
        echo ""
        echo "[+] Installation complete! Run 'fabric setup' to configure this machine."
    fi
else
    echo "[+] Installation complete (setup skipped via --no-setup)."
fi
