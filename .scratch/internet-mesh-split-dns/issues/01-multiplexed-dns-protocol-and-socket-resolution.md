# 01 — Multiplexed DNS Protocol and Dynamic Socket Resolution

**What to build:** An end-to-end WebSocket DNS query and response pipeline. The Socket receives Base64-encoded RFC 1035 DNS queries over the existing WebSocket connection, resolves queries for connected mesh nodes (`*.fabric.mesh`) against its active in-memory registry, synthesizes an A record pointing to the Socket's proxy address, returns `NXDOMAIN` (Rcode 3) for disconnected or unknown nodes, and responds with a valid RFC 1035 DNS wire message over the WebSocket.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] `protocol.DNSQuery` and `protocol.DNSResponse` JSON envelope types defined and serialized/deserialized cleanly.
- [ ] Socket control plane handles `dns_query` envelopes arriving from connected nodes and CLI clients over WebSockets.
- [ ] Active connected nodes resolve to `NOERROR` with an A record pointing to the Socket's routable reverse proxy address with a short TTL (10s).
- [ ] Offline or unregistered node hostnames resolve to `NXDOMAIN` with a short negative-cache TTL (5s).
- [ ] Wildcard subdomains (`*.node-name.fabric.mesh`) resolve to the target node.
- [ ] Unit and integration tests verify the end-to-end query/response lifecycle over WebSocket connections.
