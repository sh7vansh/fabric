Spec:
- Add a `--domain` CLI flag to the `fabric socket` command (default `fabric.mesh`).
- Add a `--domain` CLI flag to the `fabric node` command (default `fabric.mesh`).
- The DNS server should use this domain dynamically instead of the hardcoded `fabric.mesh`.
- The Node should pass this domain in the `Handshake` payload as a separate `Domain` field (Option 2 behavior), without modifying its base `Hostname`.
