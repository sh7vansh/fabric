# 03 — Discovery Output Formatting and Scriptable Flags

**What to build:**
Output presentation and CLI flag integration for `fabric stitch discover`. When running in an interactive terminal, discovered hosts must be rendered in a numbered tabular view showing index, endpoint, clean SSH banner, and latency. When running in automation pipelines, flags like `--quiet` and `--format json` must output raw machine-readable data without interactive chrome.

**Blocked by:** 02 — Concurrent TCP Prober and SSH Banner Verification

**Status:** ready-for-agent

- [ ] Renders discovered endpoints in a clean terminal table with columns: `NUM`, `ENDPOINT`, `BANNER`, and `LATENCY`.
- [ ] Outputs raw newline-delimited host addresses (`IP` or `IP:Port`) when `-q` / `--quiet` is specified.
- [ ] Outputs full structured JSON arrays of discovered hosts when `--format json` is specified.
- [ ] Provides CLI flags for `-p, --port`, `-c, --concurrency`, and `-t, --timeout`.
- [ ] Gracefully handles cases where zero SSH endpoints are discovered.
