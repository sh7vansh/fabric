# Fabric Context & Domain Glossary

Fabric is a lightweight remote execution, service discovery, and networking platform written in Go.

---

## Governing Design Principles

1. **One-Concept / One-Name Rule**: Every core concept has exactly one canonical public name.
2. **Nouns with Personality, Obvious Actions**: Fabric's nouns have personality (`thread`, `Fabric`, `peer`), and its actions stay obvious (`ps`, `exec`, `cp`, `port`, `stitch`, `init`).
3. **Mode Rule**: `local` and `remote` describe *how* a Thread operation is performed, not *what* a Thread is (`mode` != Thread type, `mode` != tag).

---

## Canonical Domain Vocabulary

- **Fabric**: The overall system and execution plane consisting of Servers and Threads connected directly or via Federation.
- **fabric**: The operator CLI binary executable.
- **Server (`fabric-server`)**: The central Fabric service that manages Threads and participates in federation (canonical: Server; Hub and Relay are deprecated).
- **Thread**: The single program/entity representing a participating machine in the Fabric (canonical: Thread; Node, Agent, Worker, and Endpoint are deprecated).
- **Operating Modes (`local` vs `remote`)**:
  - **`local` (default)**: Used when a Thread operation is performed normally against the local environment.
  - **`remote`**: Changes how the Thread operation is executed, particularly for remote/batched workflows.
  - *Invariant*: Threads do not have separate "local Thread" and "remote Thread" types. Mode describes operation execution, not machine classification.
- **Peer**: A Server-level relationship (`fabric peer ...`). A Server peers with another Server. A Peer is not a Thread.
- **Federation**: The capability/architecture that enables Servers to peer across networks and clouds.
- **Stitch**: The operation that connects/bootstraps a machine into Fabric as a Thread.
- **Init**: The operation that initializes Fabric functionality (`fabric init`).
- **Both**: Composition of Server + Thread on the same host, not a separate entity.
- **Fabric DNS**: RFC 1035-compliant DNS server embedded in `fabric-server` allowing inter-thread name resolution.
- **PTY Session**: A pseudo-terminal allocation streamed over WebSocket allowing full interactive shell access.
- **StreamMultiplexer**: A deep module wrapping the raw WebSocket to natively multiplex `io.Reader/Writer` streams using a binary protocol.
- **SystemDNSManager**: A deep module encapsulating local UDP DNS stub resolution, systemd-resolved split-DNS configuration, and `/etc/hosts` fallback mutation with deterministic teardown.
- **MeshRelay**: The central control-plane domain module in `internal/relay` encapsulating thread registration, session displacement, multiplexed stream routing, DNS wire resolution, and cluster-wide sync broadcasts.
- **ThreadDaemon (`fabric-thread`)**: The autonomous daemon module encapsulating persistent outbound connection resilience, TLS negotiation, PTY/process execution streaming, tar chunking, and deterministic teardown.
- **MeshClient**: A deep client module that encapsulates WebSocket session multiplexing, binary framing, terminal PTY state management, and RPC streaming for CLI operations (`Execute`, `Copy`, `ForwardPort`).
- **Provisioner**: An autonomous domain module in `internal/provision` for subnet discovery probing, SSH script generation, and remote host bootstrapping into the Fabric.
- **RemoteExecutor**: An adapter abstracting the SSH transport for provisioning, allowing pure testing of script generation and host bootstrapping.
- **InitManager**: A deep module in `internal/service` encapsulating multi-tier init rules (system systemd, user systemd, standalone supervisor), canonical unit/supervisor script definitions, and local lifecycle management.
- **SecureServer (`fabric-server`)**: A deep control-plane module in `internal/server` encapsulating MeshRelay, dynamic in-process TLS certificate minting, ACME autocertification, and authenticated WebSocket listeners.
- **SecureDialer**: A deep transport module in `internal/pki` encapsulating root CA auto-discovery, mTLS certificate discovery/auto-healing, and strict TLS 1.2+ encrypted WebSocket sessions.
- **AccessController**: A deep security module in `internal/server` validating capability-scoped tokens, enforcing pre-upgrade HTTP authentication, and applying sliding-window IP rate limiting.
- **ExecutionSandbox**: A deep isolation module in `internal/agent` providing POSIX credential dropping, environment variable sanitization, and deterministic process group termination.
- **StreamManager**: A deep connection bridging module in `internal/protocol` encapsulating pooled 32KB memory buffers, configurable idle deadlines, concurrency quotas, half-close TCP socket propagation, and transfer telemetry.
- **TopologyReconciler**: A deep federation module in `internal/relay` providing 64-bit monotonic generation epochs, deterministic CRC32 state checksums, and delta synchronization.

---

## Deprecated & Non-Canonical Synonyms

| Deprecated / Legacy Term | Canonical Term | Note |
|---|---|---|
| `Node` | `Thread` | Unified machine entity |
| `Agent` | `Thread` | Unified machine entity; daemon is `fabric-thread` |
| `Worker` / `Endpoint` | `Thread` | Unified machine entity |
| `Relay` / `Hub` | `Server` | Unified central control-plane service |
| `Gateway` / `GatewayID` | `Server` / `ServerID` | Unified server identity and peer relationship |
| `Local Thread` | `Thread` + `local` mode | Operational modifier, not a thread type |
| `Remote Thread` | `Thread` + `remote` mode | Operational modifier, not a thread type |

---

## System Architecture

```text
[ fabric CLI ] =====WSS/TLS=====> [ fabric-server ] <=====WSS/mTLS===== [ fabric-thread Daemon ]
(Exec/CP/Port)                   (SecureServer & DNS)                      (Thread Host Control)
                                         ▲
                                         │ Yamux Peering over WSS (Federation)
                                         ▼
                                  [ fabric-server Peer ]
```

- **Protocol**: Bidirectional JSON envelopes over encrypted WebSocket (`TypeHandshake`, `TypeExecRequest`, `TypeExecStream`, `TypeCopyRequest`, `TypeDNSQuery`, `TypeNodeSync`, `TypeServerHello`, `TypeThreadAdvertise`).
- **Binary Data**: Tar archives, raw TTY I/O, and DNS query payloads are Base64 encoded inside stream envelopes.

---

## Invariants & Design Rules

1. **Zero-Cleartext Invariant**: All transport across the Fabric (CLI, Thread, and Server Peering) is strictly TLS-encrypted (`wss://` and `https://`). Unencrypted plaintext (`ws://`, `http://`) is strictly prohibited.
2. **One Concept, One Name**: Eliminate synonyms and ambiguous terms across CLI, docs, logs, and APIs.
3. **Mode Governs Execution, Not Identity**: `local` and `remote` modify how an operation executes; they do not define distinct thread types and are not inferred from metadata tags.
4. **Outbound Only**: Threads generally never require inbound firewall holes; communication originates outbound from threads to the Fabric Server, and from Leaf servers to Core servers.
5. **Deterministic Teardown**: DNS hooks (`/etc/hosts` modifications) and PTY processes must be cleanly cleaned up on daemon shutdown or disconnect.
6. **Streaming Transfers**: File copies (`cp`) and execution streams must operate incrementally over chunked tar/stream envelopes without holding unbounded memory buffers.
7. **Obvious Verbs & Personality Nouns**: Keep standard system commands obvious (`ps`, `exec`, `cp`, `port`, `stitch`, `peer`, `init`) and conceptual nouns focused (`thread`, `Fabric`, `Server`).

---

## CLI Commands & Subcommands

```text
fabric
├── ps                                      # Quick list of connected threads (shorthand for thread ls)
├── exec [flags] <thread> [cmd...]          # Execute a command or interactive shell on a remote thread
├── cp <src> <dst>                          # Copy files/directories to/from a remote thread
├── port <thread> [local:remote]            # Forward/proxy TCP ports across the Fabric
├── peer <action>                           # Manage server-to-server federation peers
│   ├── ls                                  # List connected server peers and regions
│   ├── add <endpoint>                      # Connect to a remote server peer
│   ├── rm <server-id>                      # Disconnect a server peer
│   └── inspect <server-id>                 # Telemetry & routing table for peer
├── thread                                  # Manage Fabric threads
│   ├── ls [flags]                          # List all connected online threads
│   ├── inspect <thread...>                 # Show detailed metadata and telemetry for threads
│   └── service <action>                    # Manage local fabric-thread daemon service unit
│       ├── install                         # Install fabric-thread as a systemd service
│       ├── start                           # Start the thread daemon service
│       ├── stop                            # Stop the thread daemon service
│       ├── restart                         # Restart the thread daemon service
│       ├── status                          # Inspect thread daemon service status
│       └── uninstall                       # Remove the thread daemon service
├── stitch [flags] [TARGET | CIDR]          # Bootstrap host over SSH or scan subnet into Fabric (--mode=local|remote)
├── init [flags]                            # Initialize Fabric functionality (--role=server|thread|both --mode=local|remote)
├── agent <action>                          # [Deprecated] Alias for 'fabric thread service'
├── version                                 # Print version, build commit, and date
├── update                                  # Self-update Fabric binaries to latest release
├── uninstall                               # Completely remove Fabric, its services, and config
└── help [topic]                            # Help topics & guides (architecture, networking, security, workflows, threads, stitch)
```

### Command Reference

| Command | Description |
|---|---|
| `fabric ps` | Quick connected thread listing |
| `fabric exec <thread> [cmd]` | Run commands or attach an interactive PTY session |
| `fabric cp <src> <dst>` | Stream Tar-chunked files/directories (`thread:/path`) |
| `fabric port <thread> [local:remote]` | TCP port forwarding across the Fabric |
| `fabric peer <ls\|add\|rm\|inspect>` | Server-to-Server federation peer management |
| `fabric thread ls` | List connected threads with uptime, tags, and OS |
| `fabric thread inspect <thread>` | Detailed thread inspect output (JSON/table) |
| `fabric thread service <action>` | Manage local `fabric-thread` systemd service unit |
| `fabric stitch <host\|CIDR>` | SSH provision and join machine as a thread (`--mode=local\|remote`) |
| `fabric init` | Initialize Fabric functionality with root privileges (`sudo fabric init --role=server\|thread\|both`) |
| `fabric agent <action>` | Deprecated alias for `fabric thread service` |
| `fabric version` | Display version info |
| `fabric update` | Self-update Fabric CLI binary |
| `fabric uninstall` | Completely remove Fabric, its services, and configuration |
| `fabric help <topic>` | In-depth topic guides (`architecture`, `networking`, `security`, `workflows`, `threads`, `stitch`) |
