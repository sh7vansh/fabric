---
label: wayfinder:grilling
status: closed
depends_on:
  - 005-cli-framework-and-host-resolution.md
---
## Question

How should `fabric exec` support `-i` (interactive stdin), `-t` (PTY allocation), `-d` (detached mode), `-e` (env vars), `-w` (working dir), and handle concurrent multi-session execution on the Node?

## Resolution

- **Flag Parity:** Added `-i` (interactive stdin forward), `-t` (remote PTY allocation with local `term.MakeRaw`), `-d` (detached background execution returning session ID), `-e` (key=value environment variables), `-w` (custom working directory), and `-u` (execution user).
- **Session Multiplexing:** Added `SessionID` to `ExecRequest` and `ExecStream` payloads. The Socket routes streams per session ID to prevent cross-talk between multiple concurrent CLI executions, and Nodes maintain isolated process handles/stdin writers per session.
- **Terminal Control:** Integrated `golang.org/x/term` on the CLI to manage Raw terminal state for interactive PTY sessions.
