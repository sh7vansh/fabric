# Fabric

> A lightweight, zero-firewall remote execution, service discovery, and networking mesh written in Go.

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/sh7vansh/fabric?style=flat&color=38bdf8)](https://github.com/sh7vansh/fabric/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Fabric connects distributed servers, edge devices, and local virtual machines behind firewalls and NATs into a unified, secure mesh without requiring open inbound ports or complex VPN infrastructure.

---

## Core Capabilities

* **Zero Inbound Firewall Holes**: Nodes maintain persistent outbound WebSocket tunnels to the central Socket.
* **Interactive PTY and Fleet Execution**: Run non-interactive commands, attach full pseudo-terminals (`-i -t`), or execute across entire node fleets (`--all`, `--tag`) in parallel.
* **Embedded Mesh DNS (`.mesh`)**: Automatic RFC 1035 DNS name resolution between nodes with `systemd-resolved` split-DNS and `/etc/hosts` fallback.
* **Safe Streaming File Transfers (`cp`)**: Stream directory trees and files over Tar-chunked pipes with built-in path traversal and symlink guards.
* **TCP Port Forwarding (`port`)**: Securely bridge local ports directly to remote services across the mesh (`127.0.0.1:8080 -> worker.mesh:80`).
* **One-Shot SSH Stitching and Discovery**: Discover SSH hosts on your subnet (`stitch discover`) and bootstrap them air-gapped into the mesh with a single command.
* **Inverted and Dual-Mode mTLS**: Optional direct peer-to-peer mTLS listener mode for edge-to-CLI operations without relaying through a central socket.

---

## Quick Start

### 1. Installation

Install Fabric on any modern Linux host (`amd64`, `arm64`, `arm`):

```bash
curl -fsSL https://raw.githubusercontent.com/sh7vansh/fabric/main/install.sh | bash
```

*Or install from source:*
```bash
go install fabric/cmd/cli@latest
```

---

### 2. Basic Setup

#### Option A: Start a Socket (Central Control Plane)
Run on a publicly reachable server or central relay machine:
```bash
fabric setup --role=socket --domain=fabric.mesh
```

#### Option B: Join a Node (Agent Daemon)
Run on any host you want to manage:
```bash
fabric setup --role=node --host=ws://<socket-ip>:8080/ws --token=<your-token>
```

#### Option C: Stitch Remotely over SSH (Zero-Touch)
From your workstation, provision remote machines into your mesh automatically:
```bash
# Stitch a single machine
fabric stitch user@192.168.1.50

# Scan your subnet and batch-stitch discovered endpoints
fabric stitch discover 192.168.1.0/24
```

---

## Command Reference

### Node Management
```bash
fabric ps                           # List active nodes (shorthand)
fabric node ls                      # List connected nodes with uptime and OS
fabric node inspect worker-1        # Detailed telemetry and tags in JSON
```

### Remote Execution
```bash
# Single command execution
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
# Upload local file or folder to remote node
fabric cp ./app.tar.gz worker-1:/opt/app/

# Download remote directory to local machine
fabric cp worker-1:/var/log/ ./logs/
```

### Port Forwarding and Networking
```bash
# Forward local port 8080 to remote node's internal port 80
fabric port worker-1 8080:80

# Inspect mesh DNS target URL
fabric port worker-1
```

### Service Lifecycle
```bash
fabric service status node          # Inspect daemon service unit
fabric service restart node         # Restart background agent daemon
fabric service uninstall node       # Cleanly remove systemd/supervisor service
```

---

## Architecture Overview

```text
[ fabric CLI ] ────── WebSocket / Yamux ─────► [ fabric-socket ] ◄───── Persistent Outbound WS ───── [ fabric-node Agent ]
 (Exec / CP / Port)                              (Relay & DNS)                                         (PTY / Host Control)
```

1. **Persistent Multiplexing**: A single WebSocket connection carries multiple multiplexed streams (PTY I/O, file transfers, TCP proxies, DNS queries) via Yamux.
2. **Mesh DNS (`.mesh`)**: The Socket embeds an RFC 1035 DNS server. Node agents configure local stub resolvers so `http://worker-1.fabric.mesh` resolves seamlessly.
3. **Multi-Tier Init**: Supports root `systemd` system units, non-root `systemd --user` units with lingering, and standalone supervisor daemons for containers.

---

## Security Invariants

* **mTLS Direct Mode**: Inverted node listeners enforce Mutual TLS client certificate authentication minted by the mesh Root CA.
* **Safe Extraction**: Tar extraction enforces decompressed byte limits (5 GB max) and strict symlink escape checks to prevent zip-slip attacks.
* **Egress Filtering**: TCP proxy tunnels reject loopback and cloud-metadata IPs (e.g., AWS/GCP `169.254.169.254` and `metadata.google.internal`).
* **Constant-Time Verification**: All cluster auth tokens use cryptographic constant-time comparison.

---

## License

Fabric is open-source software released under the [MIT License](LICENSE).

