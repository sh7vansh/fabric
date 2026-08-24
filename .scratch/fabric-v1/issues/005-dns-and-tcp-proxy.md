---
status: closed
blocked_by: [001-handshake.md]
---
# Implement DNS and TCP Proxying
Bind a DNS server on the Socket (UDP 53) returning its own IP for `*.fabric.mesh`. Implement the TCP reverse proxy to intercept web traffic, wrap the raw bytes in Base64 `proxy_stream` envelopes, and multiplex them over the WebSocket to the Node.
