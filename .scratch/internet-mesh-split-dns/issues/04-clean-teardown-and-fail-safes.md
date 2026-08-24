# 04 — Clean Teardown, Service Post-Stop Hooks, and Startup Scrubbing

**What to build:** A leak-proof lifecycle management system that ensures DNS resolver configurations are cleanly reverted upon node shutdown, crash, service restart, or unexpected connection drop. The daemon traps OS termination signals (`SIGINT`, `SIGTERM`), systemd service units include automated `ExecStopPost` hooks, and startup routines scrub any stale state left behind by power outages or hard kills.

**Blocked by:** 03 — Linux systemd-resolved Split DNS Integration and /etc/hosts Fallback

**Status:** ready-for-agent

- [ ] `fabric-node` traps `SIGINT` and `SIGTERM` to invoke `resolvectl revert lo` (or clean `/etc/hosts`) before shutting down listeners.
- [ ] `fabric service install node` generates a systemd service unit containing `ExecStopPost=/usr/bin/resolvectl revert lo`.
- [ ] Node initialization routine runs an initial scrub of `lo` routing configuration on startup.
- [ ] Temporary WAN connection loss triggers retry backoff without tearing down local resolver state to avoid DNS flapping.
- [ ] Verified via `resolvectl status lo` before, during, and after process termination.
