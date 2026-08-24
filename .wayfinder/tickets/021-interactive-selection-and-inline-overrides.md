---
label: wayfinder:prototype
status: closed
depends_on:
  - 020-concurrent-ssh-port-and-banner-scanner.md
---
## Question

How should `fabric stitch discover` present discovered hosts in a terminal table, parse interactive multi-select input with inline user/port overrides (e.g. `1, admin@2, 3:2222, all`), and provide scriptable output formats (`--quiet`, `--json`, `--auto-stitch`)?

## Resolution

- **Interactive Selection & Inline Overrides ([`discover_select.go`](file:///home/shivansh/fabric/internal/cli/discover_select.go)):** Implemented `ParseSelectionInput()` supporting index tokens (`1, 3`), numeric ranges (`1-3`), target overrides (`admin@2`, `3:2222`, `root@4:2222`), wildcard `all`, and quit commands (`q`/`quit`).
- **Terminal & Machine Formatting:** `FormatDiscoveredOutput()` renders tabular summaries (`NUM ENDPOINT BANNER LATENCY`), raw newline-delimited host addresses (`--quiet`), or structured JSON objects (`--format json`).
- **Unit Tests ([`discover_select_test.go`](file:///home/shivansh/fabric/internal/cli/discover_select_test.go)):** Covered single & multi-index parsing, ranges, inline user/port mutations, direct IP overrides, and JSON/quiet serialization.
