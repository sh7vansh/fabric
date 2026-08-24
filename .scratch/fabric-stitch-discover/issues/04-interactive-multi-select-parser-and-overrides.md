# 04 — Interactive Multi-Select Parser and Overrides

**What to build:**
An interactive terminal selection interface allowing operators to choose which discovered hosts to onboard. The input parser must support comma-delimited numbers (`1, 3`), numeric ranges (`1-10`), wildcard all (`all`/`*`), cancellation (`q`/`quit`), and inline user/port overrides (e.g. `admin@2`, `3:2222`, `root@4:2222`). Also supports `--auto-stitch` / `--all` to automatically select all discovered targets in non-interactive environments.

**Blocked by:** 03 — Discovery Output Formatting and Scriptable Flags

**Status:** ready-for-agent

- [ ] Prompts the operator to select hosts from the discovery table.
- [ ] Parses individual index selections (e.g. `1, 3, 5`) and integer ranges (e.g. `1-4`).
- [ ] Parses inline username overrides (e.g. `admin@2`), port overrides (e.g. `3:2222`), and combined overrides (e.g. `root@4:2222`).
- [ ] Parses direct IP or hostname inputs passed during the selection prompt.
- [ ] Supports `all` to select all discovered hosts and `q` / `quit` to cleanly abort without error.
- [ ] Automatically selects all discovered hosts when `--auto-stitch` or `--all` is passed via CLI flags.
