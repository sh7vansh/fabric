# 01 — Subnet Auto-Detection and Target Expansion

**What to build:** 
A target generation engine for `fabric stitch discover` that automatically detects the active primary network interface and its IPv4 CIDR mask (e.g. `192.168.1.0/24`) when no target is passed, or parses user-supplied CIDR strings (`10.0.0.0/16`), single IPs, and comma-separated lists. The generator must filter out unusable network and broadcast addresses on standard subnets and enforce a safety limit of 65,536 hosts to prevent accidental massive network freezes.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] Resolves the primary outbound network interface and determines its CIDR subnet mask automatically.
- [ ] Expands standard IPv4 CIDR notation (e.g. `/24`, `/30`) into an array of usable host IP addresses.
- [ ] Automatically strips `.0` (network) and `.255` (broadcast) addresses on subnets `<= /30`.
- [ ] Enforces a maximum safety ceiling of 65,536 candidate hosts (`MaxScanHosts` / `/16`) and returns clear validation errors for excessively large subnets.
- [ ] Correctly parses comma-separated lists mixing single IPs and CIDR blocks.
