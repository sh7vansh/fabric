---
label: wayfinder:task
status: closed
---
## Question

Implement aggressive Node reconnection logic and ping/pong keepalives to gracefully handle ephemeral Socket state and dropped connections.

## Resolution

- Drafted `ConnectWithRetry` in `cmd/node/reconnect.go` implementing exponential backoff (1s up to 30s max).
- Configured `gorilla/websocket` ping/pong handlers to ensure dead TCP connections are detected and trigger the reconnection loop. 
- Because Socket state is ephemeral, Nodes will automatically rebuild the routing table upon reconnection.
