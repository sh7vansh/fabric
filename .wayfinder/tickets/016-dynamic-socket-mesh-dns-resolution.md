---
label: wayfinder:grilling
status: closed
depends_on:
  - 014-local-stub-resolver-and-dns-transport.md
---
## Question

How should the `fabric-socket` DNS engine dynamically answer queries for connected node hostnames (`<hostname>.fabric.mesh`), handle aliases/service records, and route them to the Socket's proxy or local loopback interfaces?

## Resolution

- **Dynamic In-Memory Registry Lookup:**
  - When the Socket receives a DNS query (over WebSocket or UDP 53), it strips the mesh domain suffix (`.fabric.mesh.`) to extract the target node label or alias.
  - Queries are matched in real-time against `nodesLock` map (`nodes[hostname]`).
  - If the node is currently connected and authenticated (`status: online`), the Socket responds with `NOERROR` and an `A` record pointing to the Socket's reverse proxy address (or local proxy loopback).
  - If the node is disconnected or unknown, returns `NXDOMAIN` (Rcode 3) with short negative TTL (5s) to allow instant discovery when the node reconnects.
- **Subdomain / Multi-Level Routing:**
  - Wildcard subdomain queries (`*.node1.fabric.mesh`) resolve to `node1` to support multi-tenant services, containers, and virtual hosts hosted on that node.
- **Wire-Protocol Synthesis (`miekg/dns`):**
  - Generates standard RFC 1035 wire messages, packaged in `protocol.DNSResponse` envelopes with a low TTL (10s) ensuring dynamic updates if nodes migrate or reconnect.
