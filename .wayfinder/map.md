## Destination

Zero-touch Linux deployment and automated remote onboarding: A one-liner install script (`install.sh`), an interactive `fabric setup` command that detects/configures Socket or Node roles with native `systemd` service lifecycle management, and a `fabric stitch <ssh-target>` command that remotely bootstraps and connects remote nodes to the active socket over SSH.

## Notes

- **Domain:** Linux systems administration, systemd service management, SSH automation (`crypto/ssh`), shell script bootstrapping, CLI UX (prompts/surveys).
- **Preferences:** Linux-first (systemd), pre-shared token propagation, zero-config automatic defaults, secure background daemonization, SSH remote push provisioning.
- **Tracker:** Local Markdown

## Decisions so far

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

- Sudo/root privilege escalation handling during remote `fabric stitch` over SSH when authenticated as a non-root user.
- Idempotency and auto-update / re-stitch behavior for nodes that already have a previous version installed.
- Real-time post-stitch connectivity verification loop and timeout rollback.

## Out of scope

- Non-Linux OS service management (macOS launchd, Windows services) for initial setup/systemd flows.
- Multi-cloud infrastructure provisioning APIs (AWS/GCP/Terraform integrations) — Fabric stitches via direct SSH.
- Mutual TLS (mTLS) certificate authority generation (deferred to future security phase).
