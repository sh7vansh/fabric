---
label: wayfinder:grilling
status: closed
depends_on: []
---
## Question

How should Fabric automatically generate, install, enable, start, inspect, and teardown `systemd` service units (`fabric-socket.service` and `fabric-node.service`) with environment variable injection and automatic restart policies?

## Resolution

- **Unit Generation & Management ([`service.go`](file:///home/shivansh/fabric/internal/cli/service.go)):** Added `fabric service install/start/stop/restart/status/uninstall [socket|node]` to manage native systemd units under `/etc/systemd/system/`.
- **Environment & Resilience:** Units include `EnvironmentFile=-/etc/fabric/<role>.env` and `EnvironmentFile=-%h/.fabric/<role>.env`, `Restart=always`, `RestartSec=3s`, and `LimitNOFILE=65536`.
- **Daemon Defaults:** Updated [`cmd/node/main.go`](file:///home/shivansh/fabric/cmd/node/main.go) and [`cmd/socket/main.go`](file:///home/shivansh/fabric/cmd/socket/main.go) to read `FABRIC_SOCKET_URL`, `FABRIC_HOST`, `FABRIC_TOKEN`, and `FABRIC_DOMAIN` automatically from the environment files.
- **Wizard Integration:** Embedded automatic service installation into `fabric setup` so background services can be enabled immediately upon configuration.
