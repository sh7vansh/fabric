---
status: closed
blocked_by: []
---
# Implement Core WebSocket Handshake
Setup the Go module structure. Implement the `gorilla/websocket` upgrader on the Socket and the dialer on the Node. Establish the JSON Handshake flow requiring the `FABRIC_TOKEN`. Ensure the Node implements exponential backoff on connection failure and ping/pong keepalives.
