---
label: wayfinder:task
status: closed
---
## Question

Implement the embedded DNS server on Socket (UDP 53) to serve `.fabric.mesh` records, and build the reverse-proxy mechanism to tunnel HTTP/TCP traffic down the active WebSocket to the Node.

## Resolution

- Drafted `cmd/socket/dns.go` using `miekg/dns` to resolve `*.fabric.mesh` to the Socket's IP. This directs client HTTP/TCP traffic to the Socket.
- Addressed the multiplexing fog: created `ProxyStream` JSON envelopes. Instead of a complex binary multiplexer, raw proxy TCP chunks will be Base64-encoded and sent alongside `ExecStream` payloads over the same WebSocket. The performance overhead is acceptable for v1 admin tasks.
