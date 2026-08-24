# 03 — Linux systemd-resolved Split DNS Integration and /etc/hosts Fallback

**What to build:** Zero-touch OS-level integration on Linux. When the node daemon connects, it automatically configures `systemd-resolved` via `resolvectl` to route `~fabric.mesh` exclusively to the local stub listener on `lo` with `default-route false`. This enables standard system commands (`curl http://worker-1.fabric.mesh`, `ping worker-1.fabric.mesh`) to resolve seamlessly while guaranteeing that general internet traffic (e.g. `google.com`) is never impacted. For environments without `systemd-resolved`, maintains a synchronized, atomic `/etc/hosts` managed block.

**Blocked by:** 02 — Node Local Loopback Stub Listener with Fast-Path Caching

**Status:** ready-for-agent

- [ ] Node automatically detects `systemd-resolved` availability on the host.
- [ ] Executes `resolvectl dns lo 127.0.0.1:53535` and `resolvectl domain lo ~fabric.mesh` on node startup.
- [ ] Explicitly sets `resolvectl default-route lo false` so default gateway internet queries never leak to loopback.
- [ ] Non-systemd systems gracefully fall back to maintaining a delimited `# BEGIN FABRIC MESH` / `# END FABRIC MESH` block in `/etc/hosts`.
- [ ] Standard host utilities (e.g. `curl http://node-name.fabric.mesh`, `getent hosts node-name.fabric.mesh`) resolve transparently.
