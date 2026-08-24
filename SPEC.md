# Fabric Mesh Network - V1 Specification

## 1. Overview
Fabric is a lightweight remote execution and service discovery mesh. It uses outbound reverse WebSockets to bypass NAT and firewalls, allowing a centralized routing engine to stream remote execution commands and proxy raw TCP traffic to distributed daemon nodes.

## 2. Core Architecture
* **Socket (Control Plane):** A centralized singleton routing engine. It maintains active WebSocket connections in memory, acts as an internal DNS server, and routes JSON payloads.
* **Node (Agent):** A daemon running on target machines that maintains a persistent outbound WebSocket tunnel to the Socket.
* **CLI:** The user-facing command-line client used for interacting with the mesh (e.g., `fabric exec`).

## 3. Connection & Authentication
* **Transport:** Persistent WebSockets (`ws://` or `wss://`) initiated exclusively outbound from the Node to the Socket.
* **Authentication:** Pre-shared tokens. Nodes authenticate by sending a JSON `Handshake` payload containing a token immediately upon connection. 
* **Resilience:** Nodes utilize exponential backoff (1s to 30s) and WebSocket ping/pong handlers to aggressively reconnect if the Socket connection drops. Socket routing state is strictly ephemeral and rebuilt dynamically as nodes connect.

## 4. Execution Streaming Protocol
To support interactive, SSH-like terminal sessions, execution I/O is streamed over the WebSocket via multiplexed JSON envelopes rather than a standard request/response cycle:
* `ExecRequest`: Initiates a command. Contains the target hostname, the command string, and an `allocate_pty` boolean to spin up a pseudo-terminal for interactive programs (like `vim` or `htop`).
* `ExecStream`: Carries the actual I/O chunks. Data is Base64 encoded to safely transport binary data and null bytes. Chunks are tagged by stream type (`stdout`, `stderr`, `stdin`, or `exit`).

## 5. DNS & TCP Proxying
* **DNS Server:** The Socket binds to UDP Port 53. It authoritatively resolves queries for `*.fabric.mesh` to its own IP address, directing client traffic to itself.
* **Multiplexing proxy traffic:** HTTP/TCP traffic arriving at the Socket for a mesh node is tunneled down the active WebSocket using `proxy_stream` JSON envelopes. This allows raw TCP traffic to safely share the same WebSocket connection as the structured execution payloads.

## 6. Out of Scope for V1
* **Stitcher Automation:** Automated subnet scanning and SSH payload injection.
* **Scaling:** Socket load-balancing or horizontal scaling (architecture relies on a singleton memory map).
* **Advanced Security:** Mutual TLS (mTLS) and fine-grained, role-based execution policies.
