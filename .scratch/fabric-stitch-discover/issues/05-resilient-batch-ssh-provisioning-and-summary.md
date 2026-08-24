# 05 — Resilient Batch SSH Provisioning and Summary

**What to build:**
The batch onboarding execution pipeline that iterates over selected stitch targets, invokes native OpenSSH to install the Fabric node agent and systemd service, auto-resolves loopback Socket URLs, polls the Socket for live WebSocket connection verification, isolates individual host failures without halting the batch, and renders a structured completion summary table.

**Blocked by:** 04 — Interactive Multi-Select Parser and Overrides

**Status:** ready-for-agent

- [ ] Iterates through selected targets and executes OpenSSH bootstrapping per host with active progress logging (`[*] [1/N] Stitching...`).
- [ ] Automatically resolves loopback socket URLs (e.g. `localhost` / `127.0.0.1`) to the machine's outward routable IP so remote nodes can connect.
- [ ] Polls the Socket control plane for 15 seconds to verify newly established outbound WebSocket tunnels.
- [ ] Isolates host failures (e.g. auth rejected, SSH timeout, permission denied) and continues processing remaining batch targets.
- [ ] Renders a final `Batch Stitch Summary` table upon completion displaying joined nodes, hostnames, and individual error reasons.
- [ ] Supports `--no-wait`, `-i / --identity`, `--user`, and cluster token overrides.
