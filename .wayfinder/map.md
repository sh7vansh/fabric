## Destination

V1 Fabric mesh: Node/Socket WebSocket reverse tunnels authenticated via pre-shared tokens, dynamic DNS proxying, and streaming remote execution.

## Notes

- **Domain:** Distributed systems, overlay networking, Go concurrency.
- **Preferences:** Pre-shared tokens for auth, aggressive in-memory node reconnection, both TCP proxying and exec routing over the same WebSocket, SSH-like streaming output.
- **Tracker:** Local Markdown

## Decisions so far
- [004-node-reconnection.md](tickets/004-node-reconnection.md) — Implemented exponential backoff and ping/pong keepalives on the Node.
- [003-tcp-proxying-and-dns.md](tickets/003-tcp-proxying-and-dns.md) — Implemented DNS server and resolved multiplexing by wrapping TCP traffic in `proxy_stream` JSON envelopes.
- [002-execution-streaming-protocol.md](tickets/002-execution-streaming-protocol.md) — Streaming protocol designed using chunked Base64 JSON envelopes with PTY support.
- [001-websocket-handshake.md](tickets/001-websocket-handshake.md) — Go modules initialized; WebSocket handshake with pre-shared token auth is working.

## Not yet specified


## Out of scope
- Socket load-balancing / scaling (The architecture explicitly assumes a singleton Socket for v1 due to in-memory routing).

- "Stitcher" automated subnet scanning and SSH payload injection (removed from design).
- Mutual TLS (mTLS) and role-based execution policies (deferred to future phases).
