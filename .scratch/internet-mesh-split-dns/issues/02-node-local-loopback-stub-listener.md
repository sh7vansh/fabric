# 02 — Node Local Loopback Stub Listener with Fast-Path Caching

**What to build:** An embedded UDP DNS listener running on an unprivileged loopback address (`127.0.0.1:53535`) inside the node daemon. The stub receives standard DNS queries from local tools, resolves known active peers with sub-millisecond latency from a local fast-path cache, and transparently forwards cache misses over the outbound WebSocket connection to the Socket using `dns_query` envelopes, returning the raw RFC 1035 UDP answer back to the local caller.

**Blocked by:** 01 — Multiplexed DNS Protocol and Dynamic Socket Resolution

**Status:** ready-for-agent

- [ ] `fabric-node` starts an embedded UDP DNS server on `127.0.0.1:53535` upon connection without requiring privileged port 53.
- [ ] Node maintains an in-memory cache populated from handshake and cluster metadata for instant local resolution.
- [ ] Cache misses and wildcard queries are packaged into `protocol.DNSQuery` and tunneled over the WebSocket to the Socket.
- [ ] The local stub resolver receives the `protocol.DNSResponse` and sends the raw RFC 1035 UDP response back to the querying client.
- [ ] Standard DNS tools (e.g. `dig @127.0.0.1 -p 53535 worker-1.fabric.mesh`) successfully receive valid A records.
