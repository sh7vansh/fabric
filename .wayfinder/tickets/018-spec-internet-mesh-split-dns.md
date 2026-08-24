---
label: ready-for-agent
status: closed
---
# Specification: Internet-Wide Private Split DNS Resolution for Fabric Mesh

## Problem Statement

When nodes connect to a Fabric mesh from across the public internet (behind home routers, NATs, cloud VPCs, or corporate firewalls), they cannot resolve mesh domain names like `*.fabric.mesh` natively at the OS level. Standard internet DNS queries fail because `.mesh` is a synthetic, unregistered private top-level domain. Furthermore, standard DNS queries over UDP port 53 cannot reliably traverse internet middleboxes, restrictive egress firewalls, and carrier-grade NATs without complex port forwarding or owning a publicly registered domain. 

Developers and operators need zero-configuration, native OS-level domain name resolution (`curl http://db-1.fabric.mesh`, `ssh node-1.fabric.mesh`) that works out of the box on any connected Linux machine without breaking general internet DNS or risking DNS leaks.

## Solution

A Linux-native Split DNS subsystem that integrates seamlessly with `systemd-resolved` and the Fabric WebSocket transport:
1. When a node or CLI daemon connects, it spins up a local UDP stub resolver on an unprivileged loopback address.
2. It automatically registers `~fabric.mesh` as an isolated routing domain in `systemd-resolved` via `resolvectl`, routing only `.fabric.mesh` queries to the local stub while leaving normal internet traffic untouched.
3. The local stub intercepts RFC 1035 DNS queries, checks a fast in-memory peer cache, and tunnels any cache misses across the existing outbound WebSocket connection using typed JSON envelopes.
4. The centralized Socket control plane resolves the query dynamically against its live registry of online nodes and returns synthesized A/AAAA records.
5. On shutdown, crash, or disconnect, the daemon cleanly reverts all interface routing domain configurations.

## User Stories

1. As a developer running commands on a connected node, I want to use standard hostnames like `db-1.fabric.mesh` in my scripts and tools, so that I do not need to manage or hardcode ephemeral IP addresses.
2. As a DevOps engineer, I want DNS queries for `.fabric.mesh` to be multiplexed inside the existing outbound WebSocket connection, so that DNS resolution works across strict corporate egress firewalls that block UDP port 53.
3. As a systems administrator, I want `.fabric.mesh` to be configured as a Split DNS routing domain rather than a default resolver, so that regular internet traffic (e.g. `google.com`, `github.com`) is never impacted or slowed down.
4. As a node operator, I want newly joined nodes to become resolvable across the mesh within seconds, so that automated services can immediately discover and communicate with them.
5. As a node operator, I want disconnected or offline nodes to return `NXDOMAIN` with a low negative-cache TTL, so that client applications do not hang indefinitely when attempting to connect to dead nodes.
6. As an application developer, I want wildcard subdomain resolution (such as `api.web-1.fabric.mesh` or `admin.web-1.fabric.mesh`), so that I can host multi-tenant services and virtual hosts on a single mesh node.
7. As a security engineer, I want the node daemon to automatically clean up and revert all `systemd-resolved` routing rules on shutdown, so that stale DNS resolvers are not left behind on the operating system.
8. As a site reliability engineer, I want systemd service units to include automated post-stop cleanup hooks, so that the host's DNS configuration remains clean even if the daemon crashes unexpectedly.
9. As a developer running on a minimalist Linux distribution or container without `systemd-resolved`, I want a graceful fallback that maintains a managed `/etc/hosts` synchronization block, so that basic mesh name resolution still functions without failure.
10. As a developer querying mesh services frequently, I want the local node to maintain a local fast-path in-memory cache of online peers, so that repeat lookups achieve sub-millisecond local response times without network round trips.
11. As a mesh operator managing custom networks, I want to configure custom domain suffixes (such as `*.cluster.internal`), so that my mesh can adhere to company naming standards.
12. As a CLI user running interactive commands, I want the CLI client to support ephemeral resolver binding or DNS inspection, so that I can troubleshoot mesh naming issues directly from my terminal.

## Implementation Decisions

### Local Stub Resolver Architecture
- The node daemon binds an embedded UDP DNS server on an unprivileged loopback address (`127.0.0.1:53535`) rather than privileged port 53, avoiding port-binding conflicts with `systemd-resolved` and eliminating the need for elevated network capabilities for the socket listener.
- The stub handles standard RFC 1035 wire packets and parses questions using the established DNS library.

### Split DNS Routing via systemd-resolved
- The node detects `systemd-resolved` via D-Bus / `/run/systemd/resolve/stub-resolv.conf` presence and invokes `resolvectl` to configure the loopback interface (`lo`).
- The domain is registered with a leading tilde (`~fabric.mesh`), marking it strictly as a routing domain so that only queries matching the exact suffix are directed to the loopback stub.
- Default route is explicitly disabled on the loopback interface (`default-route false`) to guarantee that default gateway DNS queries never leak to Fabric.

### Multiplexed WebSocket DNS Protocol
- DNS wire packets are transported across the active outbound WebSocket connection using typed JSON envelopes:
  - `dns_query`: Transports base64-encoded RFC 1035 query wire data alongside query metadata (session ID, target name, query type).
  - `dns_response`: Returns base64-encoded synthesized wire responses with response codes (`NOERROR`, `NXDOMAIN`) and TTL values.

### Socket-Side Dynamic Mesh Resolution
- The Socket control plane strips the configured mesh domain suffix to extract the target node identifier.
- Queries are evaluated in real-time against the Socket's active in-memory node map:
  - Online nodes resolve to the Socket's routable reverse proxy address with a short TTL (10s).
  - Offline/unknown nodes resolve to `NXDOMAIN` with a short negative cache TTL (5s).
  - Wildcard subdomains (`*.<node>.<domain>`) map dynamically to the parent node.

### Non-systemd Fallback
- On systems lacking `systemd-resolved`, the daemon detects the environment and safely manages an atomic, delimited section in `/etc/hosts` (`# BEGIN FABRIC MESH` to `# END FABRIC MESH`), updating it dynamically as node handshakes occur.

### Lifecycle Management & Clean Teardown
- Signal traps (`SIGINT`, `SIGTERM`) execute cleanup routines that invoke `resolvectl revert lo` and flush caches before closing the connection.
- Generated `systemd` service units include `ExecStopPost=/usr/bin/resolvectl revert lo` as an OS-level guarantee.
- Node startup routines execute an initial revert to scrub any stale state from prior ungraceful host reboots.

## Testing Decisions

### What Makes a Good Test
- Tests must strictly evaluate observable external behavior: submitting actual DNS queries (A/AAAA/TXT), inspecting resolved IP answers and response codes (`NOERROR`, `NXDOMAIN`), and checking OS routing state. Tests must not assert on private internal functions or state variables.

### Modules to Test
- **Protocol Envelopes:** Serialization and deserialization of `dns_query` and `dns_response` envelopes with base64 wire payloads.
- **Socket DNS Engine:** In-memory name lookup, online node resolution, offline node `NXDOMAIN` generation, and wildcard prefix matching.
- **Local Stub Resolver:** UDP packet ingestion, wire formatting, and loopback response delivery.
- **Resolver Configuration Hook:** Detection of `systemd-resolved`, generation of `resolvectl` command invocations, and `/etc/hosts` block parsing/updating.

### Prior Art
- Unit tests in `internal/protocol/envelopes_test.go` and `internal/cli/config_test.go` provide the patterns for table-driven testing and mock execution.

## Out of Scope

- Public domain registrar DNS delegation and global authoritative NS records (the mesh uses private Split DNS).
- Direct peer-to-peer kernel WireGuard mesh routing (all HTTP/TCP traffic routes through the Fabric multiplexed reverse proxy).
- Native macOS `/etc/resolver/` and Windows NRPT automated configuration (reserved for a subsequent OS expansion phase).
- DNSSEC signing and validation.

## Further Notes

- Because all DNS lookups over the WAN take place inside the existing TLS/WebSocket connection, DNS queries are fully encrypted in transit, providing built-in privacy equivalent to DNS-over-HTTPS (DoH).
