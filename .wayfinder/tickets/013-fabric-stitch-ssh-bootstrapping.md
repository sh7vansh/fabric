---
label: wayfinder:grilling
status: closed
depends_on:
  - 010-one-liner-installer-script.md
  - 011-interactive-fabric-setup-wizard.md
  - 012-systemd-service-lifecycle-management.md
---
## Question

How should `fabric stitch [user@]host[:port]` establish an SSH session, remotely bootstrap the Fabric node binaries and systemd service with current Socket host URL and token, and verify live WebSocket connection to the Socket mesh?

## Resolution

- **Remote SSH Injection ([`stitch.go`](file:///home/shivansh/fabric/internal/cli/stitch.go)):** Implemented `fabric stitch [user@]hostname` which pipes an automated bootstrap script over OpenSSH with identity key and custom port support.
- **Loopback Resolution:** Automatically detects loopback socket configurations (e.g. `localhost` / `127.0.0.1`) and resolves the outward network IP so remote nodes connect directly to the Socket.
- **Daemon Configuration & Systemd:** Remotely installs node environment configs to `/etc/fabric/node.env`, installs `fabric-node.service`, and restarts the service daemon.
- **Verification Loop:** Actively polls the Socket's `GET /nodes` endpoint for 15 seconds to confirm that the remote node has successfully established its outbound reverse WebSocket tunnel.
