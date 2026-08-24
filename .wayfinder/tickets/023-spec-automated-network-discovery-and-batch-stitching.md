---
label: ready-for-agent
status: open
---
# Specification: Automated Network Discovery & Batch Stitching (`fabric stitch discover`)

## Problem Statement

When deploying or managing Fabric across bare-metal fleets, on-premise clusters, lab environments, or enterprise subnets with dozens or hundreds of machines, manually discovering IP addresses and running individual `fabric stitch` commands for each host is tedious, error-prone, and time-consuming. Operators often lack an up-to-date inventory of available SSH servers on local or remote subnets, leading to missed machines or slow manual onboarding.

Furthermore, enterprise environments often feature mixed infrastructures where hosts have different usernames, ports, and authentication keys, or where operators need to automate batch onboarding via CI/CD pipelines and infrastructure scripts without interactive terminal prompts.

## Solution

A high-performance, concurrent network discovery and batch onboarding subsystem accessible via `fabric stitch discover [CIDR]`:
1. **Subnet Auto-Detection & Parsing**: Automatically determines the active local network interface CIDR (e.g. `192.168.1.0/24`) by default or accepts user-specified CIDRs, IP ranges, or target lists with safety bounds.
2. **Concurrent SSH Banner Grabbing**: Probes target ports using a configurable goroutine worker pool and verifies RFC 4253 SSH server identification strings (`SSH-2.0-...`) to accurately detect genuine SSH endpoints while filtering out non-SSH TCP services and honeypots.
3. **Interactive & Machine-Readable Workflows**: Displays discovered hosts in a clean terminal table, provides an interactive multi-selection prompt supporting inline user and port overrides (e.g. `1, admin@2, 3:2222, all`), and supports automated non-interactive modes (`--quiet`, `--format json`, `--auto-stitch`).
4. **Resilient Batch Stitching**: Sequentially or concurrently bootstraps selected hosts using native OpenSSH (inheriting `~/.ssh/config` rules and SSH agents), isolates individual host connection failures without stopping the batch, and provides a structured completion summary table.

## User Stories

1. As an operator deploying Fabric onto a local network, I want to run `fabric stitch discover` with zero arguments, so that Fabric automatically discovers my local subnet and finds all reachable SSH machines without me having to look up network masks.
2. As a DevOps engineer managing a large cloud VPC, I want to supply an explicit CIDR block like `fabric stitch discover 10.100.0.0/16`, so that I can scan and onboard machines in a specific remote subnet.
3. As a systems administrator, I want discovery to filter out non-SSH ports (such as web servers or load balancers on port 80/443), so that I only see authentic SSH servers in my candidate list.
4. As a network administrator scanning large subnets, I want the discovery scan to execute concurrently across a worker pool with configurable timeouts and concurrency levels, so that scanning a `/24` or `/16` subnet completes in seconds rather than minutes.
5. As an operator on an enterprise network with non-standard SSH ports, I want to specify custom ports like `--port 22,2222,2200`, so that machines running SSH on alternate ports are discovered.
6. As a security engineer scanning unknown networks, I want subnets larger than `/16` to be safely bounded, so that accidental broad scans (like `/8` or `/0`) do not overwhelm network equipment or trigger security alarms.
7. As an interactive terminal user, I want discovered hosts presented in a clear numbered table displaying endpoint IP, port, OS/SSH banner, and latency, so that I can easily identify each machine before stitching.
8. As a sysadmin onboarding a mix of servers, I want to select specific hosts by number (e.g. `1, 3, 5`), so that I only onboard the machines I choose.
9. As a developer onboarding a sequential range of lab nodes, I want to use range syntax (e.g. `1-10`), so that I do not need to type every number individually.
10. As an operator managing servers with differing credentials, I want to specify inline user overrides (e.g. `admin@2` or `root@4`), so that different machines can be stitched with their respective usernames in a single operation.
11. As an operator managing servers with differing port overrides, I want to specify inline port overrides (e.g. `3:2222`), so that machines on alternate SSH ports can be stitched in the same batch.
12. As a cloud engineer using standard `~/.ssh/config` files, I want Fabric to use native OpenSSH, so that existing host aliases, identity files, JumpHosts, and proxy commands are respected without extra configuration.
13. As an automation engineer writing Ansible/Terraform onboarding scripts, I want to pass `--format json` or `--quiet`, so that discovered host lists can be parsed programmatically by downstream automation tools.
14. As an infrastructure engineer running automated bootstrap pipelines, I want to pass `--auto-stitch` (or `--all`) and `--user <username>`, so that all discovered hosts in a subnet are automatically stitched into the mesh non-interactively.
15. As an operator running a batch stitch across 20 nodes, I want individual node failures (such as authentication rejection or host timeout) to be isolated, so that a single bad host does not abort the onboarding of the remaining 19 hosts.
16. As an operator monitoring batch onboarding, I want to see real-time progress for each node being stitched, so that I have clear visibility into the current stage of the batch.
17. As a cluster administrator, I want a structured summary table at the end of the batch stitch listing all successful and failed hosts, so that I have a clear record of which nodes successfully joined the mesh.
18. As a remote engineer whose Fabric Socket is running on localhost, I want `fabric stitch discover` to automatically resolve loopback socket URLs to reachable outbound IPs, so that remote machines can connect back to the Socket without manual URL adjustments.

## Implementation Decisions

### 1. Subnet Auto-Detection & Target Queue Generation
- Local subnet discovery probes default network routing by dialing an outward UDP connection, matches the local interface against `net.Interfaces()` to extract the exact IPv4 CIDR mask size, and defaults to a `/24` subnet.
- The target generator expands CIDR notation into candidate IPv4 host addresses while skipping network (`.0`) and broadcast (`.255`) addresses on standard subnets (`<= /30`).
- A hard ceiling limit of 65,536 hosts (`MaxScanHosts` / `/16`) is enforced to prevent unintentional network saturation.

### 2. High-Throughput Concurrent Scanner & Banner Grabbing
- Target probing is orchestrated through a channel-based worker pool with configurable worker concurrency (`default 128`) and connection timeouts (`default 1s`).
- TCP probe verification adheres to RFC 4253 § 4.2 by reading the initial server identification string and confirming the `SSH-` prefix (e.g. `SSH-2.0-OpenSSH_8.9p1 Ubuntu`). Non-SSH TCP listeners, HTTP/TLS responses, and unresponsive endpoints are discarded.
- Results are deterministically sorted by IPv4 address and port number.

### 3. Selection Parser & Interactive UX
- Interactive selection input supports single indices (`1, 3`), integer ranges (`1-4`), wildcard all (`all`/`*`), inline user overrides (`user@index`), inline port overrides (`index:port`), full overrides (`user@index:port`), and direct IP/hostname strings.
- Non-interactive automation modes are supported via `--auto-stitch`/`--all`, `--quiet`, and `--format json`.

### 4. Native OpenSSH Batch Orchestration
- Individual host bootstrapping is refactored into a reusable execution function that pipes the remote bootstrap script over standard OpenSSH subprocesses.
- Host credentials, identity files, and jump hosts inherit the operator's native `~/.ssh/config` and active `ssh-agent`.
- The batch loop executes iteratively over selected targets, isolates errors per target, continues processing on failures, and formats a final completion report table.

## Testing Decisions

- **Black-box Unit & Integration Tests**: Test external behavioral contracts (CIDR expansion, banner parsing, selection string parsing, mock server discovery) rather than internal state.
- **In-Memory Mock Network Listeners**: Use ephemeral TCP listeners on loopback to simulate authentic OpenSSH server banners, Dropbear banners, non-SSH HTTP servers, and closed ports to verify scanner discrimination without external dependencies.
- **Target Parser Matrix**: Validate edge cases across `/32` single IPs, `/30` point-to-point networks, `/24` standard subnets, out-of-range bounds, comma-separated lists, and invalid input strings.
- **Prior Art**: Follows existing CLI and protocol test patterns in `internal/cli/cli_test.go` and `cmd/socket/dns_test.go`.

## Out of Scope

- Raw SYN packet crafting requiring elevated root `CAP_NET_RAW` privileges (standard Go non-blocking TCP connect is used).
- Automated SSH password guessing or credential dictionary brute-forcing (all authentication relies on user-provided keys, SSH agent, or standard OpenSSH prompts).
- Continuous background network subnet polling / daemonized host discovery (discovery is triggered on-demand via CLI).

## Further Notes

- Subcommand structure: `fabric stitch discover [flags] [CIDR]` operates as a first-class subcommand under `fabric stitch`.
- Future extensions may add cloud provider metadata scanning (AWS EC2 / GCP Compute instance tag filtering) or mDNS/Avahi multicast discovery.
