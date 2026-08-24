# 04 — fabric cp Bidirectional Tar File & Folder Transfer

**What to build:** A `fabric cp` command supporting bidirectional file and folder copying between local filesystems and remote nodes (`local:path node:path` and `node:path local:path`) using chunked `archive/tar` streaming over WebSockets.

**Blocked by:** 01 — Cobra CLI Skeleton & 4-Tier Host/Config Resolution

**Status:** ready-for-agent

- [ ] `fabric cp` parses source and destination arguments in `[node:]path` syntax.
- [ ] Single files and nested directories are packaged into in-memory or pipe `archive/tar` streams.
- [ ] Upload mode (`local:path node:path`) packages local paths into a tar stream, sends `CopyRequest` with `Direction: upload`, streams `CopyStream` chunks, and Node unpacks to target destination.
- [ ] Download mode (`node:path local:path`) sends `CopyRequest` with `Direction: download`, Node tars the remote path, streams chunks, and CLI unpacks to local destination.
- [ ] File permissions, timestamps, directory structures, and symlinks are preserved.
- [ ] End-to-end integration tests verify bidirectional file and directory copy operations with checksum verification.
