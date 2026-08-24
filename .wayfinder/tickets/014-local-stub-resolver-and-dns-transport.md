---
label: wayfinder:grilling
status: closed
depends_on:
  - 003-tcp-proxying-and-dns.md
---
## Question

How should local DNS queries for `*.fabric.mesh` be captured on the node/client and transported over the existing outbound Fabric WebSocket connection without requiring open inbound UDP port 53 across the internet?

## Resolution

- **Local Stub Listener (`127.0.0.1:53535` / Loopback):** `fabric-node` binds a local UDP stub listener using `github.com/miekg/dns`. This avoids port 53 permission collisions with system services like `systemd-resolved`.
- **WebSocket Multiplexing (`dns_query` / `dns_response` Envelopes):** Raw RFC 1035 DNS requests are Base64-encoded into `protocol.DNSQuery` JSON envelopes and tunneled over the node's existing outbound WebSocket connection directly to `fabric-socket`.
- **Socket-side Resolution:** The Socket resolves the query against its active node map and returns a `protocol.DNSResponse` envelope containing the synthesized `dns.Msg` A/AAAA records.
- **Node-Side Fast Cache:** The node caches mesh hostnames upon handshake and node events, allowing instantaneous (<1ms) resolution of known peers while falling back to WebSocket tunneling for cache misses.
