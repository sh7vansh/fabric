# Fabric

> Lightweight, zero-firewall remote execution, discovery, and networking mesh written in Go.

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/sh7vansh/fabric?style=flat&color=38bdf8)](https://github.com/sh7vansh/fabric/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Fabric connects distributed servers, edge devices, and virtual machines behind firewalls and NATs into a unified, secure mesh without requiring open inbound ports or complex VPN infrastructure.

---

## The 3 Roles

| Role | Binary | Purpose |
|---|---|---|
| **CLI** | `fabric` | Operator tool on your laptop/workstation to run commands and manage the mesh. |
| **Server** | `fabric-server` | Central control plane and relay daemon (usually runs on a VPS or cloud server). |
| **Thread** | `fabric-thread` | Background daemon running on managed thread machines. |

---

## Quick Start

### 1. Installation

Install Fabric on any Linux system (`amd64`, `arm64`, `arm`):

```bash
curl -fsSL https://raw.githubusercontent.com/sh7vansh/fabric/main/install.sh | bash
```

### 2. Initialization

Run the onboarding wizard to configure this machine:

```bash
fabric init
```

The wizard prompts you to select how this machine participates:
- **`[1] Thread`**: Joins this machine as a Thread (`fabric-thread`).
- **`[2] Server`**: Sets up and starts the central control plane (`fabric-server`).
- **`[3] Both`**: Runs both Server and local Thread on this host.

---

## Core Workflows

### Inspect Threads
```bash
# List all active threads in the Fabric
fabric ps

# Inspect detailed thread telemetry and metadata
fabric inspect worker-1
```

### Remote Execution (`exec`)
```bash
# Run a one-off command on a thread
fabric exec worker-1 uname -a

# Interactive shell with PTY allocation
fabric exec -i -t worker-1 /bin/bash

# Execute in detached background mode
fabric exec -d worker-1 /opt/backup.sh

# Fleet-wide execution across tagged worker nodes
fabric exec --tag prod "uptime"
fabric exec --all "df -h"
```

### File Transfers (`cp`)
```bash
# Upload local file or folder to a remote thread
fabric cp ./app.tar.gz worker-1:/opt/app/

# Download a remote directory to your local machine
fabric cp worker-1:/var/log/ ./logs/
```

### TCP Port Forwarding (`port`)
```bash
# Forward local port 8080 to remote thread's internal port 80
fabric port worker-1 8080:80

# Inspect thread connectivity and DNS name
fabric port worker-1
```

### Zero-Touch SSH Stitching (`stitch`)
```bash
# Stitch a remote machine via SSH into the Fabric
fabric stitch user@192.168.1.50

# Scan your subnet and batch-stitch discovered endpoints
fabric stitch discover 192.168.1.0/24
```

### Thread Daemon Service Management
```bash
fabric thread service status       # Inspect local thread daemon status
fabric thread service restart      # Restart local thread daemon
fabric thread service uninstall    # Stop and cleanly remove background service
```

---

## Architecture Overview

```text
[ fabric CLI ] ────── WebSocket / Yamux ─────► [ fabric-server ] ◄───── Persistent Outbound WS ───── [ fabric-thread ]
 (Exec / CP / Port)                             (Relay & DNS)                                         (Managed Thread)
```

1. **Persistent Multiplexing**: A single WebSocket connection carries multiple multiplexed streams (PTY interactive sessions, file transfers, TCP port proxies, and DNS queries) via Yamux.
2. **Mesh DNS (`.mesh`)**: The Server embeds an RFC 1035 DNS server so `http://worker-1.fabric.mesh` resolves seamlessly between all threads.
3. **Multi-Tier Init**: Automatic service installation for systemd system units, non-root user units, and supervisor daemons.
4. **Direct Remote Mode**: Direct peer-to-peer mTLS listener option for edge-to-CLI operations without relaying through a central server.

---

## Security Invariants

* **mTLS Remote Mode**: Direct remote threads enforce Mutual TLS client certificate authentication minted by the mesh Root CA.
* **Safe Extraction**: Tar extraction enforces decompressed byte limits (5 GB max) and strict symlink escape checks to prevent path traversal.
* **Egress Filtering**: TCP proxy tunnels reject loopback and cloud-metadata endpoints (e.g. `169.254.169.254` and `metadata.google.internal`).
* **Constant-Time Verification**: All cluster auth tokens use cryptographic constant-time comparison.

## Dependencies

Fabric relies on the following key open-source libraries:
* [HashiCorp Yamux](https://github.com/hashicorp/yamux) — Stream multiplexing over WebSocket/TLS
* [Gorilla WebSocket](https://github.com/gorilla/websocket) — WebSocket transport protocol
* [miekg/dns](https://github.com/miekg/dns) — RFC 1035 DNS engine for Mesh DNS
* [creack/pty](https://github.com/creack/pty) — Linux pseudo-terminal allocation for interactive sessions
* [spf13/cobra](https://github.com/spf13/cobra) — Modern CLI command framework

---

## License

Fabric is open-source software released under the [MIT License](LICENSE).

