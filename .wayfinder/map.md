## Destination

Full Docker CLI parity for Fabric: A modern Cobra-powered CLI supporting Docker-style top-level commands (`fabric exec`, `fabric ps`, `fabric cp`, `fabric port`), management subcommands (`fabric node ls/inspect`), standard flags (`-i`, `-t`, `-d`, `-e`, `-w`), socket endpoint discovery via `FABRIC_HOST` / `-H` / `~/.fabric/config.json`, and the underlying multi-session & file transfer protocols.

## Notes

- **Domain:** Distributed systems, overlay networking, Go concurrency, CLI UX (Cobra/pflag), Docker command parity.
- **Preferences:** Pre-shared tokens for auth, aggressive in-memory node reconnection, both TCP proxying and exec routing over the same WebSocket, SSH-like streaming output, Docker-identical flag conventions.
- **Tracker:** Local Markdown

## Decisions so far
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
- Terminal window resize event (`SIGWINCH`) propagation across the WebSocket stream.
- Shell autocompletion generators (`fabric completion bash/zsh/fish`).

## Out of scope
- Socket load-balancing / scaling (The architecture explicitly assumes a singleton Socket for v1 due to in-memory routing).
- Container runtime management (Fabric manages bare-metal host nodes, not OCI containers/images).
- "Stitcher" automated subnet scanning and SSH payload injection (removed from design).
- Mutual TLS (mTLS) and role-based execution policies (deferred to future phases).
