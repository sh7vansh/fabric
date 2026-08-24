# 05 — fabric port Mapping Inspection & Local Forwarding Tunnels

**What to build:** A `fabric port` command that supports both inspecting node mesh port mappings (`fabric port <node>`) and creating on-demand local port-forwarding tunnels (`fabric port <node> <local_port>:<remote_port>`) through the Socket to internal Node services.

**Blocked by:** 01 — Cobra CLI Skeleton & 4-Tier Host/Config Resolution

**Status:** ready-for-agent

- [ ] `fabric port <node>` queries the Socket and displays configured DNS and port mappings (e.g. `80/tcp -> http://worker-1.fabric.mesh:80`).
- [ ] `fabric port <node> <local_port>:<remote_port>` binds a local TCP listener on `127.0.0.1:<local_port>`.
- [ ] Incoming local TCP connections are assigned a `ConnID` and forwarded as `ProxyStream` envelopes with `target_port: <remote_port>`.
- [ ] Node dials `127.0.0.1:<remote_port>` and streams raw TCP bidirectionally until either end closes.
- [ ] End-to-end integration tests verify local TCP forwarding to a mock service running on a Node.
