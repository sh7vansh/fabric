---
label: wayfinder:task
status: closed
depends_on: []
---
## Question

What is the exact specification, architecture detection (x86_64 / arm64), binary placement (`/usr/local/bin`), and execution flow for the one-liner Linux installer script (`install.sh`) to allow instant installation and chain into `fabric setup`?

## Resolution

- **Architecture & OS Validation:** Created [`install.sh`](file:///home/shivansh/fabric/install.sh) which enforces Linux-only validation and automatically determines machine architectures (`amd64`, `arm64`, `arm`).
- **Binary Placement & Sudo Handling:** Installs binaries (`fabric`, `fabric-socket`, `fabric-node`) into `/usr/local/bin` with automatic fallback to `$HOME/.local/bin` if `sudo` is unavailable.
- **Automated Handover:** Detects interactive TTY sessions and immediately launches `fabric setup` upon installation completion, while providing a `--no-setup` flag / `FABRIC_NO_SETUP=1` env override for headless/automated scripts (such as `fabric stitch`).
