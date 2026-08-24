# 03 — fabric exec Docker Parity & Multi-Session Stream Multiplexing

**What to build:** Full Docker parity for `fabric exec` supporting interactive PTY sessions (`-it`), detached background jobs (`-d`), environment variable injection (`-e`), working directory override (`-w`), and execution user (`-u`), with robust per-session stream isolation across Socket and Nodes.

**Blocked by:** 01 — Cobra CLI Skeleton & 4-Tier Host/Config Resolution

**Status:** ready-for-agent

- [ ] `fabric exec [flags] <node> <command...>` parses Docker-standard flags: `-i`, `-t`, `-d`, `-e`, `-w`, `-u`.
- [ ] `ExecRequest` and `ExecStream` payloads carry a unique `SessionID`.
- [ ] Socket multiplexes execution streams strictly between the requesting CLI and target session.
- [ ] When `-t` is passed, CLI switches local terminal to raw mode (`golang.org/x/term`) and allocates remote PTY via `pty.Start`.
- [ ] When `-d` is passed, Node spawns the command in the background and returns the session ID immediately without streaming I/O.
- [ ] Environment variables passed via `-e KEY=VAL` and working directory via `-w` are applied to the spawned process.
- [ ] Multiple concurrent executions on the same Node run simultaneously without cross-talk or race conditions.
- [ ] End-to-end integration tests verify interactive and detached execution flows.
