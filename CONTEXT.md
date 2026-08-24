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

1. **Outbound Only**: Nodes must never require inbound firewall holes; all communication originates outbound from nodes to the Socket.
2. **Deterministic Teardown**: DNS hooks (`/etc/hosts` modifications) and PTY processes must be cleanly cleaned up on node shutdown or disconnect.
3. **Streaming Transfers**: File copies (`cp`) and execution streams must operate incrementally over chunked tar/stream envelopes without holding unbounded memory buffers.
