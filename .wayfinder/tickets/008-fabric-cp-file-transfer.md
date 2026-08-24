---
label: wayfinder:prototype
status: closed
depends_on:
  - 005-cli-framework-and-host-resolution.md
---
## Question

What protocol and streaming mechanism should Fabric use to copy files/directories bidirectionally between the local machine and remote nodes (`local:path node:path` and `node:path local:path`)?

## Resolution

- **Transfer Format:** Adopted bidirectional `archive/tar` streaming over WebSockets, matching Docker's internal file transfer mechanism (handling files, directories, permissions, symlinks, and timestamps natively).
- **Envelopes:** Added `CopyRequest` (with `TransferID`, `Direction: "upload"|"download"`, `RemotePath`) and `CopyStream` (chunked Base64 tar data with `IsEOF` termination flag).
- **Socket Routing:** Sockets multiplex copy streams via `TransferID` directly between the initiating CLI client and the target Node daemon.
