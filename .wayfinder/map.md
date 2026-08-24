## Destination

Internet-wide private mesh DNS resolution for `*.fabric.mesh`: Automatic Linux Split DNS configuration (`systemd-resolved` / local stub resolver) that routes mesh queries through the persistent outbound Fabric WebSocket tunnel without requiring public domain registrations or open inbound UDP port 53.

## Notes

- **Domain:** DNS protocols (RFC 1035), Linux network resolvers (`systemd-resolved`, `resolvectl`, `nsswitch`, `/etc/resolv.conf`), local stub listeners, WebSocket multiplexing.
- **Preferences:** Linux-first (systemd-resolved), zero-touch automatic configuration on node connect, clean lifecycle teardown, secure multiplexed transport over existing WebSocket.
- **Tracker:** Local Markdown

## Decisions so far

- [017-node-dns-lifecycle-and-clean-teardown.md](tickets/017-node-dns-lifecycle-and-clean-teardown.md) — Implemented graceful signal reverts, systemd `ExecStopPost` fail-safes, and startup scrubbing for leak-free resolver teardown.
- [016-dynamic-socket-mesh-dns-resolution.md](tickets/016-dynamic-socket-mesh-dns-resolution.md) — Implemented dynamic in-memory registry lookup with NXDOMAIN for offline nodes and wildcard subdomain routing.
- [015-linux-systemd-resolved-split-dns-integration.md](tickets/015-linux-systemd-resolved-split-dns-integration.md) — Configured `resolvectl` on loopback with routing domain `~fabric.mesh` and `/etc/hosts` sync fallback for non-systemd environments.
- [014-local-stub-resolver-and-dns-transport.md](tickets/014-local-stub-resolver-and-dns-transport.md) — Captured local DNS queries via loopback stub resolver (`127.0.0.1:53535`) and multiplexed RFC 1035 wire packets over WebSocket via `dns_query`/`dns_response` envelopes.
- [013-fabric-stitch-ssh-bootstrapping.md](tickets/013-fabric-stitch-ssh-bootstrapping.md) — Built `fabric stitch [user@]host` to remotely bootstrap node daemon configs and verify live WebSocket connection.
- [012-systemd-service-lifecycle-management.md](tickets/012-systemd-service-lifecycle-management.md) — Built `fabric service` CLI and daemon environment integration for systemd service generation, installation, and lifecycle.
- [011-interactive-fabric-setup-wizard.md](tickets/011-interactive-fabric-setup-wizard.md) — Implemented `fabric setup` wizard with role selection (Socket/Node), secure token generation, config persistence, and join output.
- [010-one-liner-installer-script.md](tickets/010-one-liner-installer-script.md) — Built `install.sh` for Linux (`amd64`/`arm64`) with `/usr/local/bin` installation, sudo fallback, and interactive handover to `fabric setup`.
- [009-fabric-port-and-forwarding.md](tickets/009-fabric-port-and-forwarding.md) — Designed dual-mode `fabric port` for mesh port inspection and interactive local-to-remote TCP port forwarding tunnels via `ProxyStream` (`TargetPort`).
- [008-fabric-cp-file-transfer.md](tickets/008-fabric-cp-file-transfer.md) — Implemented bidirectional `archive/tar` chunk streaming over WebSockets for `fabric cp` (matching Docker's file/folder copy mechanics).
- [007-fabric-exec-docker-parity.md](tickets/007-fabric-exec-docker-parity.md) — Implemented Docker `-it`, `-d`, `-e`, `-w` flags, per-session ID multiplexing across Socket/Node, and local terminal raw mode via `golang.org/x/term`.
- [006-fabric-ps-and-node-metadata.md](tickets/006-fabric-ps-and-node-metadata.md) — Selected REST HTTP `GET /nodes` endpoint for fast querying, enriched `Handshake` with OS/version, and Docker tabular formatting (`-q`, `--format json`).
- [005-cli-framework-and-host-resolution.md](tickets/005-cli-framework-and-host-resolution.md) — Adopted Cobra framework with Docker-parity hybrid command tree and 4-tier config resolution (Flags > Env > Config JSON > Defaults).
- [004-node-reconnection.md](tickets/004-node-reconnection.md) — Implemented exponential backoff and ping/pong keepalives on the Node.
- [003-tcp-proxying-and-dns.md](tickets/003-tcp-proxying-and-dns.md) — Implemented DNS server and resolved multiplexing by wrapping TCP traffic in `proxy_stream` JSON envelopes.
- [002-execution-streaming-protocol.md](tickets/002-execution-streaming-protocol.md) — Streaming protocol designed using chunked Base64 JSON envelopes with PTY support.
- [001-websocket-handshake.md](tickets/001-websocket-handshake.md) — Go modules initialized; WebSocket handshake with pre-shared token auth is working.

## Not yet specified

- macOS split DNS integration via `/etc/resolver/fabric.mesh`.
- Windows DNS client / NRPT (Name Resolution Policy Table) integration.
- Custom domain namespaces per tenant / network cluster (`*.company.internal`).
- Dynamic SRV / TXT service discovery records registered by nodes.

## Out of scope

- Public domain registrar DNS delegation / global public authoritative NS setup (we are using private Split DNS / Option B).
- Direct peer-to-peer WireGuard kernel overlay routing (v1 routes through Fabric's multiplexed reverse proxy engine).
