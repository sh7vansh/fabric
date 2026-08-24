---
label: wayfinder:prototype
status: closed
depends_on:
  - 013-fabric-stitch-ssh-bootstrapping.md
---
## Question

How should `fabric stitch discover [CIDR]` auto-detect active local network interfaces (e.g. `192.168.1.0/24`, `10.0.0.0/24`), parse user-supplied CIDR blocks or IP ranges, exclude broadcast/network addresses, and generate candidate scan targets?

## Resolution

- **Subnet Auto-Detection ([`discover.go`](file:///home/shivansh/fabric/internal/cli/discover.go)):** `GetDefaultLocalCIDR()` inspects the local default routing interface via outbound probe, extracts the exact subnet mask size from `net.Interfaces()`, and falls back to a `/24` network mask.
- **CIDR Expansion & Safety Limit:** `ParseTargets()` parses explicit CIDRs, comma-separated ranges, or individual IPs, skips `.0` (network) and `.255` (broadcast) addresses on subnets `<= /30`, and enforces a safety limit of 65,536 hosts (`MaxScanHosts` / `/16`) to prevent network freezes.
- **Unit Tests ([`discover_test.go`](file:///home/shivansh/fabric/internal/cli/discover_test.go)):** Comprehensive test suite covering single hosts, `/32`, `/30`, `/24`, comma-separated targets, invalid syntax, and out-of-bounds safety guards.
