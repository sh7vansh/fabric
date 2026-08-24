---
label: wayfinder:grilling
status: closed
depends_on:
  - 015-linux-systemd-resolved-split-dns-integration.md
  - 016-dynamic-socket-mesh-dns-resolution.md
---
## Question

How should the DNS resolver configuration be safely reverted upon node shutdown, crash, or unexpected connection drop to prevent DNS leaks or broken internet name resolution on the host?

## Resolution

- **Graceful Signal Handling (SIGINT/SIGTERM):**
  - Node daemon captures termination signals and invokes `resolvectl revert lo` (or clears `/etc/hosts` managed block) before shutting down the local stub listener and closing the WebSocket.
- **Systemd Unit Resilience (`ExecStopPost`):**
  - In `fabric-node.service`, systemd unit specifies `ExecStopPost=/usr/bin/resolvectl revert lo`. This ensures systemd cleanly restores the interface resolver state even if the daemon process experiences a fatal panic or `SIGKILL` (kill -9).
- **Startup Hygiene:**
  - Upon starting, `fabric-node` performs an initial `resolvectl revert lo` to scrub any stale resolver state left behind by ungraceful power cuts.
- **Fail-Safe Split Isolation:**
  - Because `~fabric.mesh` is bound exclusively as a routing domain with `default-route false`, an offline stub never interrupts default internet gateway DNS resolution for the host.
- **Transient Connection Drop Handling:**
  - During temporary WAN disconnects, the node retains its loopback listener while backing off/reconnecting, returning `SERVFAIL` rather than deregistering from systemd to avoid resolver flapping.
