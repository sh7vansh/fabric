# ADR 001: Fabric CLI Terminology, Grammar & Architecture Redesign

## Status
**Accepted** (Ratified: 2026-08-25)

---

## Context & Motivation

The original Fabric implementation exposed internal infrastructural details (`fabric-socket`, `fabric-node`, `normal` vs `inverted` connection modes, and raw "mesh" terminology) directly in user-facing CLI commands, flags, and help guides. This created friction, steepened the learning curve, and obscured the system's operational simplicity.

To establish a cohesive product identity and intuitive operator experience, we establish a core guiding principle:

> **Fabric's nouns have personality (`thread`, `Fabric`). Its actions stay obvious (`ps`, `exec`, `cp`, `port`, `stitch`).**

---

## Decision

### 1. Domain Vocabulary Mapping

| Legacy Concept | New Standard Term | User Context / Rationale |
|---|---|---|
| `node` | `thread` | User-facing unit of compute; a machine stitched into the Fabric. |
| `node ID` | `thread name` / `thread ID` | Human-readable identifier for a thread (e.g. `worker-1`). |
| `Socket` / `fabric-socket` | `Fabric server` / `gateway` (`fabric-server`) | Control-plane & relay server; hidden from standard workflows. |
| `node agent` / `fabric-node` | `Fabric agent` (`fabric-agent`) | Daemon running on each thread host maintaining outbound tunnels. |
| `mesh` / `node topology` | `Fabric` / `network` | The overall interconnected environment. |
| `mesh DNS` | `Fabric DNS` / `DNS` | Embedded DNS name resolution for `.mesh` / `.fabric` domains. |
| `normal` vs `inverted` | `local` vs `remote` | User-centric perspective for direct/mTLS connection topologies. |
| `stitch` | `stitch` | Onboarding/joining a machine into Fabric as a thread. |

---

### 2. Binary Architecture & Packaging

The system is factored into three purpose-built binaries:

1. **`fabric` (Operator CLI)**:
   - Primary CLI tool used by operators to interact with threads, transfer files, execute commands, and bootstrap machines.
   - Built from `cmd/cli/main.go` to `bin/fabric`.
2. **`fabric-server` (Control Plane & Gateway)**:
   - Central WebSocket relay, session multiplexer, cluster mTLS coordinator, and embedded DNS server.
   - Built from `cmd/server/main.go` to `bin/fabric-server`.
3. **`fabric-agent` (Thread Daemon)**:
   - Autonomous background daemon running on managed hosts.
   - Maintains persistent outbound WebSocket connections to the Fabric server, executes streaming PTY sessions, handles tar chunking, and configures local DNS hooks.
   - Built from `cmd/agent/main.go` to `bin/fabric-agent`.

---

### 3. CLI Command Hierarchy

```text
fabric
├── ps                                      # Quick list of connected threads
├── exec [flags] <thread> [cmd...]          # Execute command or interactive PTY session
├── cp <src> <dst>                          # Stream file/directory transfers (thread:/path)
├── port <thread> [local:remote]            # TCP port forward or list mappings
├── thread                                  # Thread management
│   ├── ls [flags]                          # List connected threads (--format json, -q, -l)
│   └── inspect <thread...>                 # Detailed telemetry & metadata
├── stitch [flags] [TARGET | CIDR]          # Onboard machine or discover subnet
├── init [flags]                            # Onboarding & workspace initialization wizard
├── agent <action>                          # Manage local thread daemon systemd unit
│   ├── install                             # Install systemd service for fabric-agent
│   ├── start                               # Start background agent service
│   ├── stop                                # Stop background agent service
│   ├── restart                             # Restart background agent service
│   ├── status                              # Inspect agent service status
│   └── uninstall                           # Remove background agent service
├── version                                 # Display version and build info
├── update                                  # Self-update Fabric CLI binary
├── uninstall                               # Remove Fabric installation and config
└── help [topic]                            # Built-in topic guides
```

---

### 4. `fabric stitch` Polymorphism & Subnet Discovery

`fabric stitch` serves as the universal machine onboarding command:

1. **Single Target Mode** (`fabric stitch user@192.168.1.50`):
   - Establishes direct SSH session, installs `fabric-agent`, configures unit, and verifies thread joins Fabric.
2. **Subnet Discovery Mode** (`fabric stitch 192.168.1.0/24`):
   - Concurrently scans target CIDR on SSH ports, renders a discovery table, and provides an interactive host selector (`1, admin@2, 3:2222`, `all`, `q`).
   - `--all` / `--batch` allows fully non-interactive batch provisioning.
3. **Auto-Discovery Mode** (`fabric stitch` with no arguments):
   - Auto-detects local subnet CIDR and initiates discovery.

---

### 5. `fabric init` vs `fabric agent`

- **`fabric init`**:
  - Interactive onboarding wizard configuring the operator's local environment (`~/.fabric/config.json`), setting server WebSocket URLs, cluster tokens, and root CA trust (`--trust-ca`).
  - Architecture flags (`--role=node`, `--role=socket`) are removed.
- **`fabric agent`**:
  - Replaces `fabric service [node|socket]`.
  - Manages the local thread daemon systemd unit (`install`, `start`, `stop`, `restart`, `status`, `uninstall`) using multi-tier init detection (system systemd, user systemd, supervisor).

---

### 6. Backward Compatibility & Deprecation Strategy

During the transition period, deprecated subcommands and flags remain functional as aliases and output a clear stderr warning:

- `fabric node ls` $\rightarrow$ `Warning: 'fabric node' is deprecated. Use 'fabric thread' instead.`
- `fabric service ...` $\rightarrow$ `Warning: 'fabric service' is deprecated. Use 'fabric agent' instead.`
- `fabric setup` $\rightarrow$ `Warning: 'fabric setup' is deprecated. Use 'fabric init' instead.`
- `fabric stitch discover <CIDR>` $\rightarrow$ `Warning: 'fabric stitch discover' is deprecated. Use 'fabric stitch <CIDR>' instead.`
- Flags: `--server` / `-s` (primary) with fallback to `--host` / `-H`; `--remote` (primary) with fallback to `--direct` and `--inverted`.
- Environment variables: `FABRIC_THREAD_*` and `FABRIC_SERVER_*` with fallback to `FABRIC_NODE_*` and `FABRIC_SOCKET_*`.

---

### 7. Built-in Help System

CLI help is rewritten to avoid internal socket-node diagrams in favor of clear user concepts:
- Topics: `architecture`, `networking`, `security`, `workflows`.
- New dedicated guides: `threads`, `stitch`.

---

## Consequences

- **User Experience**: Operators interact with intuitive, high-level primitives (`threads`, `Fabric`) without needing to understand low-level socket-node relay topology.
- **Maintainability**: Clear separation of concerns between operator tooling (`fabric`), relay/gateway (`fabric-server`), and execution daemon (`fabric-agent`).
- **Consistency**: Standardized command nouns, verbs, and flags across all workflows.
