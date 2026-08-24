---
label: wayfinder:grilling
status: closed
depends_on:
  - 014-local-stub-resolver-and-dns-transport.md
---
## Question

How should `fabric-node` and the `fabric` CLI automatically register and configure Split DNS routing for `~fabric.mesh` using `systemd-resolved` (via `resolvectl` / D-Bus) and fallback gracefully on systems without `systemd-resolved`?

## Resolution

- **`systemd-resolved` Detection:** `fabric-node` detects if `systemd-resolved` is running by verifying `systemctl is-active systemd-resolved` or checking the `/run/systemd/resolve/stub-resolv.conf` presence.
- **Routing Domain Registration (`~fabric.mesh`):**
  - Executes `resolvectl dns lo 127.0.0.1:53535` and `resolvectl domain lo ~fabric.mesh` (with `systemd-resolve` fallback on older distros).
  - The leading tilde (`~`) designates `fabric.mesh` strictly as a routing domain so regular internet traffic (e.g. `google.com`) is untouched and never sent to Fabric.
  - Configures `resolvectl default-route lo false` to prevent loopback from capturing default gateway lookups.
- **Non-systemd / Container Fallback:**
  - On minimalist systems or Docker containers without `systemd-resolved`, `fabric-node` checks `/etc/resolv.conf`. If unmanaged, it maintains a managed comment block in `/etc/hosts` (`# BEGIN FABRIC MESH ... # END FABRIC MESH`) synced from live node events.
- **Privilege Handling:**
  - Under systemd service execution (`fabric-node.service`), daemon privileges configure `resolvectl` directly.
  - In CLI interactive mode, uses `sudo` if necessary or outputs clean one-line setup instructions.
