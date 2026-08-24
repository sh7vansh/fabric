# Fabric Context & Domain Glossary

Fabric is a lightweight remote execution, service discovery, and networking mesh written in Go.

---

## Domain Vocabulary

- **Socket (`fabric-socket`)**: The central control-plane and relay server. Coordinates WebSocket tunnels, TCP proxying, and Mesh DNS.
- **Node (`fabric-node`)**: The managed agent daemon running on host machines, maintaining persistent outbound WebSocket connections to the Socket.
- **CLI (`fabric`)**: The operator tool used to execute commands, transfer files, inspect nodes, and bridge networks.
- **Mesh DNS**: RFC 1035-compliant DNS server embedded in `fabric-socket` (defaulting to the `.mesh` TLD) allowing inter-node name resolution.
- **PTY Session**: A pseudo-terminal allocation streamed over WebSocket allowing full interactive shell access.
- **Stitch / Discover**: Automated subnet scanner and SSH provisioning mechanism to bootstrap remote targets into the mesh.
- **StreamMultiplexer**: A deep module wrapping the raw WebSocket to natively multiplex `io.Reader/Writer` streams using a binary protocol, replacing manual JSON stream chunking.
- **SystemDNSManager**: A deep module encapsulating local UDP DNS stub resolution, systemd-resolved split-DNS configuration, and `/etc/hosts` fallback mutation with deterministic teardown.
- **MeshRelay**: The central control-plane domain module in `internal/relay` encapsulating node registration, session displacement, multiplexed stream routing (exec, copy, proxy), DNS wire resolution, and cluster-wide sync broadcasts.
- **NodeAgent**: The autonomous daemon module in `internal/agent` encapsulating persistent outbound connection resilience, TLS negotiation, PTY/process execution streaming, tar chunking, and deterministic teardown.
- **MeshClient**: A deep client module that encapsulates WebSocket session multiplexing, binary framing, terminal PTY state management, and RPC streaming for CLI operations (`Execute`, `Copy`, `ForwardPort`).
- **Provisioner**: An autonomous domain module in `internal/provision` for subnet discovery probing, SSH script generation, and remote host bootstrapping into the mesh.
- **RemoteExecutor**: An adapter abstracting the SSH transport for provisioning, allowing pure testing of script generation and host bootstrapping.
- **Inverted Connection Mode**: An edge-case deployment mode where a Node acts as the server listening on a public port (`--listen`) and the operator uses the CLI (`--direct`) to bypass the Socket. Supported via Mutual TLS (mTLS).

---

## System Architecture

```
[ fabric CLI ] ----WebSocket----> [ fabric-socket ] <----WebSocket---- [ fabric-node Agent ]
(Exec/CP/Port)                        (Relay & DNS)                       (PTY / Host Control)
```

- **Protocol**: Bidirectional JSON envelopes over WebSocket (`TypeHandshake`, `TypeExecRequest`, `TypeExecStream`, `TypeCopyRequest`, `TypeDNSQuery`, `TypeNodeSync`).
- **Binary Data**: Tar archives, raw TTY I/O, and DNS query payloads are Base64 encoded inside stream envelopes.

---

## Invariants & Design Rules

1. **Outbound Only**: Nodes generally must never require inbound firewall holes; communication originates outbound from nodes to the Socket. (Exception: Inverted Connection Mode where a node acts as the mTLS server).
2. **Deterministic Teardown**: DNS hooks (`/etc/hosts` modifications) and PTY processes must be cleanly cleaned up on node shutdown or disconnect.
3. **Streaming Transfers**: File copies (`cp`) and execution streams must operate incrementally over chunked tar/stream envelopes without holding unbounded memory buffers.

---

## CLI Commands & Subcommands

```
fabric
├── exec              # Execute a command or interactive shell on a remote node
├── ps                # List active nodes (convenience shorthand for node ls)
├── cp                # Copy files/directories to/from a remote node
├── port              # Forward/proxy TCP ports across the mesh
├── setup             # Interactive CLI and configuration onboarding wizard
├── version           # Print version, build commit, and date
├── node              # Manage fabric nodes
│   ├── ls            # List all connected online nodes
│   └── inspect       # Show detailed metadata and telemetry for a specific node
├── stitch            # Bootstrap & provision a remote host over SSH into the mesh
│   └── discover      # Scan local or specified CIDR subnet for SSH hosts to stitch
├── service           # Manage background systemd service lifecycle
│   ├── install       # Install fabric as a systemd service
│   ├── start         # Start the fabric service
│   ├── stop          # Stop the fabric service
│   ├── restart       # Restart the fabric service
│   ├── status        # Inspect fabric service status
│   └── uninstall     # Remove the systemd service
└── help [topic]      # Help topics & guides (architecture, networking, security, workflows)
```

### Command Reference

| Command | Description |
|---|---|
| `fabric exec <node> [cmd]` | Run commands or attach an interactive PTY session |
| `fabric ps` | Quick node listing |
| `fabric cp <src> <dst>` | Stream Tar-chunked files/directories |
| `fabric port <local:remote>` | TCP port forwarding across the mesh |
| `fabric node ls` | List connected nodes with uptime and OS |
| `fabric node inspect <node>` | Detailed node inspect output (JSON/table) |
| `fabric stitch <host>` | SSH provision and join a remote node |
| `fabric stitch discover [CIDR]` | Subnet scan and batch SSH provisioning |
| `fabric setup` | Interactive setup helper for config/keys |
| `fabric service <action>` | Manage background `systemd` service unit |
| `fabric version` | Display version info |
| `fabric help <topic>` | In-depth topic guides (`architecture`, `networking`, `security`, `workflows`) |


