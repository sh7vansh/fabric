---
status: closed
blocked_by: [003-command-streaming.md]
---
# Implement PTY Allocation
Update the Node's execution engine to check the `allocate_pty` boolean. If true, use a library like `creack/pty` to spin up a pseudo-terminal instead of standard pipes, enabling interactive sessions (e.g., `vim`, `htop`).
