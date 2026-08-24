## Destination

Automated Network Discovery & Batch Stitching (`fabric stitch discover`): Subnet auto-detection, concurrent SSH banner scanning, interactive inline target selection (`1, admin@2, 3:2222`), and resilient multi-node onboarding into the Fabric mesh.

## Notes

- **Domain:** Network discovery, subnet IP generation, concurrent TCP/SSH banner grabbing, CLI TUI interaction, OpenSSH batch orchestration.
- **Preferences:** Native OpenSSH integration (inherits `~/.ssh/config` & `ssh-agent`), zero external dependencies, fast goroutine scanning with timeout safeguards, fault-tolerant batch execution with clear summary reporting.
- **Tracker:** Local Markdown

## Decisions so far

- [022-batch-stitch-orchestration-and-summary.md](tickets/022-batch-stitch-orchestration-and-summary.md) — Built `fabric stitch discover` CLI command, fault-tolerant batch execution loop, OpenSSH bootstrap integration, and summary table reporting.
- [021-interactive-selection-and-inline-overrides.md](tickets/021-interactive-selection-and-inline-overrides.md) — Implemented terminal tabular output, index ranges, inline user/port overrides (`admin@2`, `3:2222`), and JSON/quiet formatters.
- [020-concurrent-ssh-port-and-banner-scanner.md](tickets/020-concurrent-ssh-port-and-banner-scanner.md) — Built concurrent worker pool scanner, RFC 4253 SSH banner verification, latency profiling, and mock listener test suite.
- [019-subnet-and-target-range-discovery.md](tickets/019-subnet-and-target-range-discovery.md) — Implemented local network interface auto-detection, CIDR expansion, broadcast/network address scrubbing, and safety host limits in `ParseTargets()`.
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

- mDNS / Avahi local multicast discovery fallback for zero-configuration LANs.
- Automatic node tag / metadata assignment during batch discovery.
- Cloud provider metadata discovery plugins (AWS EC2, GCP Compute, Azure VM tag scanning).

## Out of scope

- Raw SYN packet crafting requiring root raw-socket capabilities (we use standard Go non-blocking TCP connect + SSH banner read).
- Automated password brute-forcing / dictionary attacks (all authentication relies on user-provided or SSH config keys).
