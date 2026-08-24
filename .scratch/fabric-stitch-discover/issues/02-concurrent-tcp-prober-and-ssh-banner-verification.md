# 02 — Concurrent TCP Prober and SSH Banner Verification

**What to build:**
A high-throughput concurrent scanning engine that takes candidate IP targets and probes them across port 22 (or user-defined ports). The prober must read the initial server identification string and confirm adherence to the RFC 4253 SSH protocol format (`SSH-2.0-...`), cleanly discarding non-SSH services, HTTP/TLS servers, and closed/unresponsive endpoints. Probing must run across a goroutine worker pool with configurable concurrency and per-probe timeouts.

**Blocked by:** 01 — Subnet Auto-Detection and Target Expansion

**Status:** ready-for-agent

- [ ] Concurrently probes target IPs using a channel-based worker pool with configurable concurrency (default 128 workers).
- [ ] Connects via TCP and reads the initial identification string with strict deadline timeouts (default 1s).
- [ ] Confirms the server identification string begins with `SSH-` (RFC 4253) and extracts cleaned banner metadata (e.g. `OpenSSH_8.9p1 Ubuntu`).
- [ ] Safely rejects non-SSH TCP listeners (e.g. HTTP, HTTPS, telnet) and closed ports without throwing fatal errors.
- [ ] Measures and records connection latency per discovered host.
- [ ] Deterministically sorts discovered host results by IPv4 address and port number.
