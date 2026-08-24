---
label: wayfinder:prototype
status: closed
---
## Question

Design and prototype the JSON envelope protocol to support streaming stdout/stderr and stdin over the WebSocket instead of bulk request/response, simulating an SSH-like data flow.

## Resolution

Agreed on a chunked JSON envelope model:
- `ExecRequest` initiates the session, containing the `command` and an `allocate_pty` boolean.
- `ExecStream` multiplexes the actual data chunks in both directions using `stream` ("stdout", "stderr", "stdin", "exit").
- Raw stream data is Base64 encoded to safely transport null bytes and binary data inside JSON payloads.
- The `allocate_pty` flag settles the need for interactive shell allocations.
