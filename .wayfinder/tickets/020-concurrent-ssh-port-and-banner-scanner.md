---
label: wayfinder:prototype
status: closed
depends_on:
  - 019-subnet-and-target-range-discovery.md
---
## Question

How should the network scanner concurrently probe port 22 (or user-defined `--port`), grab and verify the `SSH-2.0-...` identification banner to eliminate false positives, and manage connection timeouts and worker pool concurrency (e.g. `--concurrency`, `--timeout`)?

## Resolution

- **RFC 4253 SSH Banner Verification ([`discover_scan.go`](file:///home/shivansh/fabric/internal/cli/discover_scan.go)):** `probeSSH()` dials the TCP endpoint, sets strict read timeouts, and verifies that the initial response begins with `SSH-` (cleaning prefixes like `SSH-2.0-`), filtering out HTTP, TLS, honeypots, and non-SSH services.
- **Concurrent Worker Pool Engine:** `ScanTargets()` uses a buffered job queue with configurable concurrency (`default 128 workers`), per-host timeout controls, real-time `onFound` callbacks, and deterministic IP/Port sorting.
- **Unit Tests with Mock Servers ([`discover_scan_test.go`](file:///home/shivansh/fabric/internal/cli/discover_scan_test.go)):** Validated with live in-memory mock SSH listeners (OpenSSH, Dropbear), mock HTTP servers, and closed port rejection.
