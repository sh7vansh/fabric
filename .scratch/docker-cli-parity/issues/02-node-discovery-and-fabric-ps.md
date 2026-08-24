# 02 — Node Discovery & fabric ps / fabric node ls

**What to build:** Commands to inspect and list connected mesh nodes (`fabric ps` as a top-level alias and `fabric node ls`), querying an authenticated REST endpoint on the Socket (`GET /nodes`) and formatting tabular output matching `docker ps`.

**Blocked by:** 01 — Cobra CLI Skeleton & 4-Tier Host/Config Resolution

**Status:** ready-for-agent

- [ ] Node agent sends enriched metadata on `Handshake` (OS, architecture, agent version, hostname, domain).
- [ ] Socket maintains connection uptime and last heartbeat timestamp for each connected node.
- [ ] Socket exposes `GET /nodes` REST endpoint protected by Bearer token authentication.
- [ ] `fabric ps` and `fabric node ls` print a formatted table with columns: `NODE ID`, `HOSTNAME`, `STATUS`, `IP`, `DOMAIN`, `UPTIME`.
- [ ] `-q` / `--quiet` flag outputs only node IDs/hostnames for easy piping.
- [ ] `--format json` outputs a raw JSON array of active node records.
- [ ] End-to-end tests verify node registration, metadata tracking, and CLI listing output.
