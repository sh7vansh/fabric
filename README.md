# Fabric

Fabric is a lightweight remote execution, service discovery, and networking mesh written in Go. It allows you to manage and connect to multiple remote machines seamlessly without needing inbound firewall rules.

## One-Click Installation

To install Fabric on any modern Linux system (Ubuntu, Fedora, Debian, CentOS, etc.), simply run this command in your terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/sh7vansh/fabric/main/install.sh | bash
```

### What this script does:
1. Detects your OS and architecture (`amd64`, `arm64`, or `arm`).
2. Downloads the pre-compiled binaries from the latest GitHub Release.
3. Places them in `/usr/local/bin` (or `~/.local/bin` if run without `sudo`).
4. Automatically launches the interactive `fabric setup` wizard to get your node connected!

## Architecture Highlights
* **Outbound Only**: Nodes generally must never require inbound firewall holes; communication originates outbound from nodes to the central Socket. 
  * *(Edge Case: Supports an "Inverted Connection Mode" where a node can safely expose a public port via strict mTLS, allowing operators behind strict NATs to bypass the central socket using the CLI `--direct` flag).*
* **Deterministic Teardown**: DNS hooks (`/etc/hosts` modifications) and PTY processes are cleanly cleaned up on node shutdown or disconnect.
* **Streaming Transfers**: File copies (`cp`) and execution streams operate incrementally over chunked tar/stream envelopes without holding unbounded memory buffers.
