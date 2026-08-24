---
label: wayfinder:grilling
status: closed
depends_on: []
---
## Question

How should the interactive `fabric setup` command guide the user through role selection (Socket vs Node), automatically generate cryptographically secure tokens, configure network endpoints / domains, persist `~/.fabric/config.json`, and display ready-to-use join instructions?

## Resolution

- **Interactive & Headless Modes:** Added `fabric setup` ([`setup.go`](file:///home/shivansh/fabric/internal/cli/setup.go)) supporting both interactive CLI prompts and non-interactive scripted invocations (`--role`, `--auto-token`, `--yes`, `--token`, `--host`).
- **Socket Workflow:** Generates cryptographically secure 32-character cluster tokens, configures mesh DNS domain (`fabric.mesh`), saves CLI defaults to `~/.fabric/config.json`, writes daemon environment config to `/etc/fabric/socket.env` (or `~/.fabric/socket.env`), and outputs ready-to-copy `fabric stitch` and `fabric setup --role=node` join commands.
- **Node Workflow:** Configures the target Socket WebSocket URL and cluster token, persists local configuration, writes `/etc/fabric/node.env`, and prepares the machine for daemon startup.
