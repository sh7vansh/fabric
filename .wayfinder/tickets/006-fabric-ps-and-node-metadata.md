---
label: wayfinder:grilling
status: closed
---
## Question

How should the Socket track, health-check, and serve active Node metadata (hostname, uptime, IP, status, version) for formatted tabular output in `fabric ps` / `fabric node ls` (HTTP REST vs WebSocket query)?

## Resolution

- **Endpoint Transport:** Selected HTTP REST (`GET /nodes` and `GET /nodes/{hostname}`) with Bearer token authentication for fast, connectionless querying.
- **Node Metadata Registry:** Extended `Handshake` envelope to collect OS, version, and architecture. Socket enriches this with client `RemoteIP`, `ConnectedAt` (for uptime calculations), and `LastSeen` (updated via WebSocket ping/pong keepalives).
- **Tabular Formatting & Docker Flags:** Implemented `text/tabwriter` column output (`NODE ID`, `HOSTNAME`, `STATUS`, `IP`, `DOMAIN`, `UPTIME`), `-q`/`--quiet` flag, and `--format json`/template support.
