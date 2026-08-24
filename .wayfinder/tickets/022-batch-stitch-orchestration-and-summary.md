---
label: wayfinder:prototype
status: closed
depends_on:
  - 021-interactive-selection-and-inline-overrides.md
  - 013-fabric-stitch-ssh-bootstrapping.md
---
## Question

How should the batch stitch execution engine orchestrate multi-host provisioning via native OpenSSH, stream progress and live verification per node, handle individual host authentication/network failures gracefully without halting the batch, and output a structured completion summary?

## Resolution

- **CLI Discover Subcommand ([`stitch.go:stitchDiscoverCmd`](file:///home/shivansh/fabric/internal/cli/stitch.go#L43-L48)):** Registered `fabric stitch discover [CIDR]` supporting auto-detected subnets, configurable scan parameters (`--port`, `--timeout`, `--concurrency`), and automation flags (`--auto-stitch` / `--all`, `--quiet`, `--format json`).
- **Resilient Batch Orchestration ([`stitch.go:ExecuteStitchHost`](file:///home/shivansh/fabric/internal/cli/stitch.go#L254-L373)):** Refactored single-host provisioning into a reusable executor that pipes the installation script over OpenSSH, automatically resolves loopback socket addresses to reachable outbound IPs, and polls the Socket for live WebSocket connection verification.
- **Fault-Tolerant Execution Loop ([`stitch.go:runStitchDiscover`](file:///home/shivansh/fabric/internal/cli/stitch.go#L112-L252)):** Iterates through selected targets, captures successes and failures independently, logs per-host errors without aborting remaining hosts, and renders a structured `Batch Stitch Summary` table upon completion.
