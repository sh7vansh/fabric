# Fabric

> Lightweight, zero-firewall remote execution, service discovery, and networking mesh written in Go.

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/sh7vansh/fabric?style=flat&color=38bdf8)](https://github.com/sh7vansh/fabric/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Fabric connects distributed servers, edge devices, and virtual machines behind firewalls and NATs into a unified, secure execution mesh without requiring open inbound firewall ports or complex VPN setups.

---

## The 3 Binaries

| Binary | Role | Description |
|---|---|---|
| **`fabric`** | **CLI** | Operator tool to execute commands, transfer files, forward ports, and inspect the mesh. |
| **`fabric-server`** | **Server** | Central control plane, TLS cert minting, embedded DNS, and federation routing. |
| **`fabric-thread`** | **Thread** | Autonomous daemon running on participating machines connected outbound. |

---

## Quick Start

### 1. Installation

Install Fabric on any Linux system (`amd64`, `arm64`, `arm`):

```bash
curl -fsSL https://raw.githubusercontent.com/sh7vansh/fabric/main/install.sh | bash
```

### 2. Initialization

Run the onboarding wizard to configure the host:

```bash
fabric init
```

Choose how this machine participates:
- **`[1] Thread`**: Joins this machine as a managed Thread (`fabric-thread`).
- **`[2] Server`**: Initializes the central control-plane service (`fabric-server`).
- **`[3] Both`**: Runs both Server and Thread on the same machine.

---

## Core Commands

### Inspect & Discovery
```bash
# List all online connected threads
fabric ps

# Detailed thread inspection & telemetry
fabric thread inspect worker-1
```

### Remote Execution (`exec`)
```bash
# Run a one-off command
fabric exec worker-1 uname -a

# Interactive shell with full PTY allocation
fabric exec -i -t worker-1 /bin/bash

# Run in detached background mode
fabric exec -d worker-1 /opt/backup.sh

# Batch execution across tagged threads or all threads
fabric exec --tag prod "uptime"
fabric exec --all "df -h"
```

### File Transfers (`cp`)
```bash
# Upload a file or directory (streamed via chunked tar)
fabric cp ./app.tar.gz worker-1:/opt/app/

# Download files from a remote thread
fabric cp worker-1:/var/log/ ./local-logs/
```

### TCP Port Forwarding (`port`)
```bash
# Forward local port 8080 to remote thread's port 80
fabric port worker-1 8080:80
```

### Server Peering & Federation (`peer`)
```bash
# Connect to another Fabric server across regions or clouds
fabric peer add https://eu-west.fabric.internal:8443

# List peered servers and active routing tables
fabric peer ls

# Inspect telemetry for a specific peer
fabric peer inspect srv-eu-west
```

### SSH Stitching (`stitch`)
```bash
# Bootstrap and join a remote machine into Fabric over SSH
fabric stitch user@192.168.1.50

# Scan a local subnet and batch-stitch discovered endpoints
fabric stitch 192.168.1.0/24
```

### Thread Service Management
```bash
fabric thread service status       # Check daemon systemd/supervisor status
fabric thread service restart      # Restart thread daemon
fabric thread service uninstall    # Cleanly remove service and DNS entries
```

---

## Architecture & Features

```text
[ fabric CLI ] ────── WSS / TLS ──────► [ fabric-server ] ◄───── Outbound WSS / mTLS ───── [ fabric-thread ]
(Exec / CP / Port)                        │ (Relay & DNS)                                  (Execution Sandbox)
                                          │
                                   Yamux Peering (WSS)
                                          │
                                 [ fabric-server Peer ]
```

- **Outbound-Only Connectivity**: Threads connect outbound to the Server over persistent TLS WebSockets—no inbound firewall rules or port forwarding required.
- **Embedded Mesh DNS (`.mesh`)**: RFC 1035-compliant DNS server inside `fabric-server` resolves `http://worker-1.fabric.mesh` across all threads automatically.
- **Multi-Server Federation**: Monotonic generation epochs and Merkle CRC32 checksums guarantee consistent routing and automatic delta recovery across multi-region servers.
- **Sandboxed Execution**: Process group isolation (`SIGTERM` $\to$ `SIGKILL` escalation), POSIX credential dropping, and environment variable sanitization protect worker machines.
- **Flow-Controlled Streaming**: Deep 32KB buffer pooling, TCP half-close propagation, configurable idle deadlines, and transfer telemetry across all proxy tunnels.
- **Access Control**: Capability-scoped authentication tokens (`inspect`, `exec`, `copy`, `proxy`, `admin`) with sliding-window IP rate limiting.

---

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



