---
label: wayfinder:task
status: closed
---
## Question

Establish the core Go projects for Socket, Node, and CLI. Implement the initial persistent WebSocket connection with pre-shared token authentication and the JSON Handshake envelope.

## Resolution

- Initialized Go module `fabric`.
- Added `github.com/gorilla/websocket`.
- Created `cmd/socket`, `cmd/node`, `cmd/cli`, and `internal/protocol`.
- Implemented a basic WebSocket upgrader in Socket that expects a JSON Handshake containing a pre-shared token (`FABRIC_TOKEN`).
- Implemented Node dialer that connects and sends the authenticated Handshake payload.
