---
status: closed
blocked_by: [001-handshake.md]
---
# Implement Execution Request Routing
Define the `ExecRequest` and `ExecStream` JSON envelopes. Implement the routing memory map in the Socket (associating hostnames to active WebSockets) so that an `ExecRequest` from the CLI is successfully forwarded to the target Node.
