---
label: wayfinder:grilling
status: closed
depends_on:
  - 005-cli-framework-and-host-resolution.md
---
## Question

How should the CLI inspect mapped ports on nodes (`fabric port <node>`) or establish local port forwarding tunnels to services running on mesh nodes?

## Resolution

- **Dual-Mode Ergonomics:** Implemented both Docker-parity port inspection (`fabric port <node>`) and on-demand local port-forwarding tunnels (`fabric port <node> <local_port>:<remote_port>`).
- **Protocol Extension:** Extended `ProxyStream` with `TargetPort` to support forwarding arbitrary TCP ports (e.g. databases, HTTP services) across the existing WebSocket tunnel without opening additional ports on the Node firewall.
