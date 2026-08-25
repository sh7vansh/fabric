# Fabric Context & Domain Glossary

Fabric is a lightweight remote execution, service discovery, and networking platform written in Go.

---

## Governing Design Principle

> **Fabric's nouns have personality (`thread`, `Fabric`). Its actions stay obvious (`ps`, `exec`, `cp`, `port`, `stitch`).**

---

## Domain Vocabulary

- **Fabric**: The interconnected network and execution plane connecting distributed machines.
- **Thread**: A managed machine or remote execution target stitched into the Fabric (identified by a unique thread name/ID).
- **Fabric Server (`fabric-server`)**: The central control-plane gateway and relay server. Coordinates WebSocket tunnels, TCP proxying, and Fabric DNS.
- **Fabric Agent (`fabric-agent`)**: The managed agent daemon running on host machines, maintaining persistent outbound WebSocket connections to the Fabric Server.
- **Fabric CLI (`fabric`)**: The operator tool used to execute commands, transfer files, inspect threads, and bridge networks.
- **Fabric DNS**: RFC 1035-compliant DNS server embedded in `fabric-server` (defaulting to the `.mesh` / `.fabric` TLD) allowing inter-thread name resolution.
- **PTY Session**: A pseudo-terminal allocation streamed over WebSocket allowing full interactive shell access.
- **Stitch / Discover**: Automated subnet scanner and SSH provisioning mechanism to bootstrap remote targets into the Fabric as threads.
- **StreamMultiplexer**: A deep module wrapping the raw WebSocket to natively multiplex `io.Reader/Writer` streams using a binary protocol, replacing manual JSON stream chunking.
- **SystemDNSManager**: A deep module encapsulating local UDP DNS stub resolution, systemd-resolved split-DNS configuration, and `/etc/hosts` fallback mutation with deterministic teardown.
- **MeshRelay**: The central control-plane domain module in `internal/relay` encapsulating thread registration, session displacement, multiplexed stream routing (exec, copy, proxy), DNS wire resolution, and cluster-wide sync broadcasts.
- **NodeAgent / ThreadAgent**: The autonomous daemon module in `internal/agent` encapsulating persistent outbound connection resilience, TLS negotiation, PTY/process execution streaming, tar chunking, and deterministic teardown.
- **MeshClient**: A deep client module that encapsulates WebSocket session multiplexing, binary framing, terminal PTY state management, and RPC streaming for CLI operations (`Execute`, `Copy`, `ForwardPort`).
- **Provisioner**: An autonomous domain module in `internal/provision` for subnet discovery probing, SSH script generation, and remote host bootstrapping into the Fabric.
- **RemoteExecutor**: An adapter abstracting the SSH transport for provisioning, allowing pure testing of script generation and host bootstrapping.
- **InitManager**: A deep module in `internal/service` encapsulating multi-tier init rules (system systemd, user systemd, standalone supervisor), canonical unit/supervisor script definitions, and local lifecycle management or remote script rendering.
- **Local vs Remote**: User-centric connection topologies. In standard operation, agents initiate outbound connections to the server; in direct remote mode, an agent listens directly with mTLS.

---

## System Architecture

```text
[ fabric CLI ] ----WebSocket----> [ fabric-server Gateway ] <----WebSocket---- [ fabric-agent Daemon ]
(Exec/CP/Port)                           (Relay & DNS)                             (Thread / Host Control)
```

- **Protocol**: Bidirectional JSON envelopes over WebSocket (`TypeHandshake`, `TypeExecRequest`, `TypeExecStream`, `TypeCopyRequest`, `TypeDNSQuery`, `TypeNodeSync`).
- **Binary Data**: Tar archives, raw TTY I/O, and DNS query payloads are Base64 encoded inside stream envelopes.

---

## Invariants & Design Rules

1. **Outbound Only**: Threads generally never require inbound firewall holes; communication originates outbound from agents to the Fabric Server.
2. **Deterministic Teardown**: DNS hooks (`/etc/hosts` modifications) and PTY processes must be cleanly cleaned up on agent shutdown or disconnect.
3. **Streaming Transfers**: File copies (`cp`) and execution streams must operate incrementally over chunked tar/stream envelopes without holding unbounded memory buffers.
4. **Obvious Verbs & Personality Nouns**: Keep standard system commands obvious (`ps`, `exec`, `cp`, `port`, `stitch`) and conceptual nouns focused (`thread`, `Fabric`).

---

## CLI Commands & Subcommands

```text
fabric
├── ps                                      # Quick list of connected threads (shorthand for thread ls)
├── exec [flags] <thread> [cmd...]          # Execute a command or interactive shell on a remote thread
├── cp <src> <dst>                          # Copy files/directories to/from a remote thread
├── port <thread> [local:remote]            # Forward/proxy TCP ports across the Fabric
├── thread                                  # Manage Fabric threads
│   ├── ls [flags]                          # List all connected online threads
│   └── inspect <thread...>                 # Show detailed metadata and telemetry for threads
├── stitch [flags] [TARGET | CIDR]          # Bootstrap host over SSH or scan subnet into Fabric
├── init [flags]                            # Interactive CLI and configuration onboarding wizard
├── agent <action>                          # Manage background fabric-agent systemd service
│   ├── install                             # Install fabric-agent as a systemd service
│   ├── start                               # Start the agent service
│   ├── stop                                # Stop the agent service
│   ├── restart                             # Restart the agent service
│   ├── status                              # Inspect agent service status
│   └── uninstall                           # Remove the agent systemd service
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
| `fabric thread ls` | List connected threads with uptime, tags, and OS |
| `fabric thread inspect <thread>` | Detailed thread inspect output (JSON/table) |
| `fabric stitch <host>` | SSH provision and join a remote host as a thread |
| `fabric stitch [CIDR]` | Subnet scan and batch SSH provisioning |
| `fabric init` | Interactive setup helper for local operator config/keys |
| `fabric agent <action>` | Manage local `fabric-agent` systemd service unit |
| `fabric version` | Display version info |
| `fabric update` | Self-update Fabric CLI binary |
| `fabric uninstall` | Completely remove Fabric, its services, and configuration |
| `fabric help <topic>` | In-depth topic guides (`architecture`, `networking`, `security`, `workflows`, `threads`, `stitch`) |
