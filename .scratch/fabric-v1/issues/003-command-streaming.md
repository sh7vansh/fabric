---
status: closed
blocked_by: [002-execution-routing.md]
---
# Implement I/O Command Streaming
Implement `os/exec` on the Node. Attach pipes to `stdout`/`stderr` and `stdin`, read in chunks, Base64 encode them, and wrap them in `ExecStream` envelopes. On the CLI side, decode these envelopes and stream them to the user's terminal.
