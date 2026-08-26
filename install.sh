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
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || echo "")"
if [ -n "$REPO_DIR" ] && [ -f "$REPO_DIR/go.mod" ] && command -v go >/dev/null 2>&1; then
    echo "[+] Building canonical Fabric binaries from source..."
    (cd "$REPO_DIR" && go build -o "$TMP_DIR/fabric" ./cmd/cli)
    (cd "$REPO_DIR" && go build -o "$TMP_DIR/fabric-server" ./cmd/server)
    (cd "$REPO_DIR" && go build -o "$TMP_DIR/fabric-thread" ./cmd/thread)
else
    # Check if download URL or release is configured
    RELEASE_TAG="${FABRIC_VERSION:-latest}"
    if [ "$RELEASE_TAG" = "latest" ]; then
        DOWNLOAD_URL_PREFIX="${FABRIC_DOWNLOAD_URL:-https://github.com/sh7vansh/fabric/releases/latest/download}"
    else
        DOWNLOAD_URL_PREFIX="${FABRIC_DOWNLOAD_URL:-https://github.com/sh7vansh/fabric/releases/download/$RELEASE_TAG}"
    fi
    
    echo "[+] Attempting to download Fabric ($RELEASE_TAG) for linux/$FABRIC_ARCH..."
    if command -v curl >/dev/null 2>&1; then
        # Download checksum manifest first
        echo "[+] Fetching checksums manifest..."
        curl -fsSL "$DOWNLOAD_URL_PREFIX/checksums.txt" -o "$TMP_DIR/checksums.txt" 2>/dev/null || true

        for role in "fabric" "fabric-server" "fabric-thread"; do
            asset="${role}-linux-${FABRIC_ARCH}"
            echo "[+] Downloading $asset..."
            if [ -t 1 ]; then
                curl -fL --progress-bar "$DOWNLOAD_URL_PREFIX/$asset" -o "$TMP_DIR/$asset" 2>&1 || true
            else
                curl -fsSL "$DOWNLOAD_URL_PREFIX/$asset" -o "$TMP_DIR/$asset" || true
            fi
            if [ -f "$TMP_DIR/$asset" ]; then
                size="$(du -h "$TMP_DIR/$asset" 2>/dev/null | awk '{print $1}' || echo "")"
                if [ -n "$size" ]; then
                    echo "[+] Downloaded $asset ($size)"
                fi
            fi
        done
    elif command -v wget >/dev/null 2>&1; then
        echo "[+] Fetching checksums manifest..."
        wget -q "$DOWNLOAD_URL_PREFIX/checksums.txt" -O "$TMP_DIR/checksums.txt" 2>/dev/null || true

        for role in "fabric" "fabric-server" "fabric-thread"; do
            asset="${role}-linux-${FABRIC_ARCH}"
            echo "[+] Downloading $asset..."
            if [ -t 1 ]; then
                wget --show-progress -q -O "$TMP_DIR/$asset" "$DOWNLOAD_URL_PREFIX/$asset" || true
            else
                wget -q -O "$TMP_DIR/$asset" "$DOWNLOAD_URL_PREFIX/$asset" || true
            fi
            if [ -f "$TMP_DIR/$asset" ]; then
                size="$(du -h "$TMP_DIR/$asset" 2>/dev/null | awk '{print $1}' || echo "")"
                if [ -n "$size" ]; then
                    echo "[+] Downloaded $asset ($size)"
                fi
            fi
        done
    fi

    # Verify SHA-256 checksums if manifest is available
    if [ -f "$TMP_DIR/checksums.txt" ] && command -v sha256sum >/dev/null 2>&1; then
        echo "[+] Verifying cryptographic SHA-256 checksums..."
        (
            cd "$TMP_DIR"
            for role in "fabric" "fabric-server" "fabric-thread"; do
                asset="${role}-linux-${FABRIC_ARCH}"
                if [ -f "$asset" ]; then
                    expected="$(grep -E "[[:space:]]\*?${asset}$" checksums.txt | awk '{print $1}' || true)"
                    if [ -z "$expected" ]; then
                        echo "[-] Error: Checksum for $asset not found in manifest"
                        exit 1
                    fi
                    actual="$(sha256sum "$asset" | awk '{print $1}')"
                    if [ "$expected" != "$actual" ]; then
                        echo "[-] Error: Security checksum mismatch for $asset (expected $expected, got $actual)"
                        exit 1
                    fi
                    mv "$asset" "$role"
                fi
            done
        )
    elif [ -f "$TMP_DIR/fabric-linux-$FABRIC_ARCH" ]; then
        echo "[-] Error: Checksum manifest missing or sha256sum tool not found. Cannot verify binary integrity."
        exit 1
    fi

    # Fallback to Go build if binaries were not downloaded and Go is available
    if [ ! -f "$TMP_DIR/fabric" ] && command -v go >/dev/null 2>&1; then
        echo "[+] Building Fabric binaries using Go toolchain..."
        GOBIN="$TMP_DIR" go install fabric/cmd/cli@latest 2>/dev/null || true
        GOBIN="$TMP_DIR" go install fabric/cmd/server@latest 2>/dev/null || true
        GOBIN="$TMP_DIR" go install fabric/cmd/thread@latest 2>/dev/null || true
        [ -f "$TMP_DIR/cli" ] && mv "$TMP_DIR/cli" "$TMP_DIR/fabric" || true
        [ -f "$TMP_DIR/server" ] && mv "$TMP_DIR/server" "$TMP_DIR/fabric-server" || true
        [ -f "$TMP_DIR/thread" ] && mv "$TMP_DIR/thread" "$TMP_DIR/fabric-thread" || true
    fi
fi

# Ensure binaries exist
if [ -f "$TMP_DIR/fabric" ]; then
    echo "[+] Installing canonical binaries into $INSTALL_DIR..."
    $SUDO install -m 0755 "$TMP_DIR/fabric" "$INSTALL_DIR/fabric"
    if [ -f "$TMP_DIR/fabric-server" ]; then
        $SUDO install -m 0755 "$TMP_DIR/fabric-server" "$INSTALL_DIR/fabric-server"
    fi
    if [ -f "$TMP_DIR/fabric-thread" ]; then
        $SUDO install -m 0755 "$TMP_DIR/fabric-thread" "$INSTALL_DIR/fabric-thread"
    fi
else
    echo "[-] Error: Canonical Fabric binaries could not be compiled or downloaded."
    exit 1
fi

echo "[+] Fabric successfully installed to $INSTALL_DIR/fabric"

# 5. Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "[!] Warning: $INSTALL_DIR is not in your PATH."
    echo "    Add it by running: export PATH=\"\$PATH:$INSTALL_DIR\""
fi

# 6. Handover to Init
if [ "$NO_SETUP" -eq 0 ]; then
    echo ""
    echo "========================================="
    echo "   Fabric Network Port Prerequisites"
    echo "========================================="
    echo "  • Fabric Server / Control Plane: Port 8443/TCP (inbound)"
    echo "  • Fabric Thread (Local Mode):     Outbound-only (no inbound ports required)"
    echo "  • Fabric Thread (Remote Mode):    Port 8443/TCP (inbound direct mTLS)"
    echo "  • Remote Stitching (SSH):         Port 22/TCP (inbound on target)"
    echo "========================================="

    if [ -t 0 ] && command -v "$INSTALL_DIR/fabric" >/dev/null 2>&1; then
        echo ""
        echo "[+] Launching Fabric onboarding wizard..."
        "$INSTALL_DIR/fabric" init || true
    else
        echo ""
        echo "[+] Installation complete! Run 'fabric init' to configure this machine."
    fi
else
    echo "[+] Installation complete (setup skipped via --no-setup)."
fi

