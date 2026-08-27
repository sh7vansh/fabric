# ADR 004: Embedded Userspace WireGuard Engine & Device Access Architecture

## Status
**Accepted** (Ratified: 2026-08-27)

---

## Context & Motivation

Fabric provides lightweight remote execution, file streaming, and service discovery across compute nodes (`Threads`) running the `fabric-thread` daemon over outbound TLS/WebSocket connections. While this model is ideal for Linux servers, developer workstations, and edge compute boxes, consumer devices (iOS, iPadOS, Android, Smart TVs, macOS) cannot easily execute unprivileged background Go daemons or accept SSH provisioning (`fabric stitch <host>`).

However, standard **WireGuard** client applications are ubiquitous across mobile and consumer platforms. 

To allow operators to securely access Fabric services (e.g. `http://nas.fabric:8080`, `ssh devbox.fabric`) directly from phones, tablets, and TVs without compromising Fabric's core zero-inbound-firewall-hole invariant or polluting host networking, Fabric requires an **Embedded Userspace WireGuard Subsystem** in `fabric-server`.

---

## Decision

### 1. Pure Userspace WireGuard Engine (`wireguard-go` + `gvisor/netstack`)

`fabric-server` embeds a pure Go userspace WireGuard implementation via `golang.zx2c4.com/wireguard/device` and `golang.zx2c4.com/wireguard/tun/netstack` (backed by gVisor's `gvisor.dev/gvisor/pkg/tcpip`).

```text
[ iOS / Android / TV ]
        │ WireGuard App (UDP :51820)
        ▼
[ fabric-server (Userspace Process) ]
  ├── wireguard-go (device.Device over standard UDP socket)
  ├── gVisor netstack (Virtual In-Memory TCP/IP Stack)
  ├── Virtual IPAM Subnet (100.64.0.0/10 — Server at 100.64.0.1)
  ├── In-Memory DNS Server (100.64.0.1:53 -> Relay.ResolveDNS)
  └── Stream Multiplexer Bridge (100.64.0.X:PORT -> Relay.RouteProxyStream)
        │
        ▼ Yamux over WSS/TLS
[ fabric-thread Daemon ]
```

#### Invariants:
* **Zero Root / Zero Capabilities**: Requires no `sudo`, `CAP_NET_ADMIN`, or `/dev/net/tun`.
* **Zero Host Routing / Firewall Mutation**: No Linux `wg0` interfaces are created, and host `iptables`/`nftables` rules are never modified.
* **Hermetic Isolation**: All decrypted WireGuard packets reside exclusively in Go process memory.

---

### 2. Domain Vocabulary & Conceptual Distinction

Fabric adheres to the **One-Concept / One-Name Rule**:

| Concept | Canonical Noun | Role & Definition |
|---|---|---|
| **Thread** | `Thread` | Compute engine running `fabric-thread` daemon. Participates in execution, file chunking, and port forwarding. |
| **Device** | `Device` | Client/consumer endpoint connecting via standard WireGuard. Consumes `.fabric` services and DNS; does not execute remote commands. |
| **Server** | `Server` | Central control plane and gateway managing Threads, Devices, and Peers. |

---

### 3. Overlay Subnet & IPAM Architecture

Fabric allocates a non-colliding Carrier-Grade NAT (CGNAT) overlay range:

* **Overlay CIDR**: `100.64.0.0/10`
* **Fabric Server & Gateway**: `100.64.0.1`
* **Threads (Compute)**: `100.64.0.2` – `100.64.127.254` (dynamically assigned upon WebSocket handshake).
* **Devices (Clients)**: `100.64.128.1` – `100.64.255.254` (persisted on pairing).

#### Split Routing Policy:
Generated WireGuard profiles configure:
* `AllowedIPs = 100.64.0.0/10` (only internal Fabric traffic is routed through the tunnel).
* `DNS = 100.64.0.1` (queries for `.fabric` route to Fabric Server; public queries can be recursively forwarded or resolved locally).

---

### 4. In-Memory DNS Interception & Delegation

`fabric-server` initializes an in-memory `miekg/dns` server attached directly to the `netstack` virtual packet connection (`net.PacketConn`) at `100.64.0.1:53`.

1. Mobile client requests A record for `worker-1.fabric`.
2. Packet arrives on virtual UDP `:53` inside userspace `netstack`.
3. DNS handler queries `Relay.ResolveDNS` / IPAM table in memory.
4. Synthesizes `worker-1.fabric. 10 IN A 100.64.0.42` response and transmits back across the WireGuard tunnel.

---

### 5. Transparent Userspace TCP Stream Bridging

When a WireGuard device initiates a TCP connection to `100.64.0.X:<port>`:

1. `netstack`'s virtual TCP listener accepts the `net.Conn`.
2. Destination IP is looked up in the IPAM table to resolve the target Thread hostname.
3. `fabric-server` constructs a `protocol.ProxyRequest` envelope:
   ```json
   {
     "type": "proxy_request",
     "target_hostname": "worker-1",
     "target_host": "127.0.0.1",
     "target_port": 8080
   }
   ```
4. Stream is handed to `Relay.RouteProxyStream`, which opens a Yamux stream over the existing WSS/TLS tunnel to the thread daemon (`fabric-thread`).
5. Data transfers are proxied bidirectionally via `protocol.StreamManager.Bridge` using flow-controlled 32KB memory pools.

---

### 6. CLI Grammar & Pairing UX

Onboarding uses the canonical `stitch` action, supporting mobile QR scanning, TV/headless pairing web portals, and direct config export:

```text
fabric
├── stitch device <name>              # Generate WireGuard keypair, IP, QR code & .conf profile
│   └── flags:
│       ├── --qr                      # Display ASCII QR code in terminal (default: true)
│       ├── --web                     # Host ephemeral local pairing web portal for TVs/headless (default: true)
│       ├── --out=<path>              # Output config file path (default: <name>.conf)
│       └── --subnet=<cidr>           # Custom subnet override
├── device                            # Manage client devices
│   ├── ls                            # List all paired devices (Name, IP, Public Key, Status, Tx/Rx)
│   ├── inspect <name>                # Inspect device configuration and routing details
│   └── rm <name>                     # Revoke device key and reclaim virtual IP
```

#### Headless & Smart TV Onboarding Flows:
1. **QR Scan**: Direct scan via phone/tablet camera into the WireGuard app.
2. **Ephemeral Pairing Portal (`--web`)**: Generates an expiring local URL (`http://<local-ip>:8080/pair/<name>`) and 6-digit code for easy TV web browser download.
3. **Profile File Export (`--out`)**: Generates `<name>.conf` for USB/SMB/ADB import onto TVs.
4. **Ecosystem Cloud Sync**: Apple TV automatically syncs WireGuard tunnels configured on iOS via iCloud Keychain.

---

## Consequences & Invariants Maintained

1. **Zero Architecture Disruption**: Existing thread communication, CLI commands (`fabric ps`, `fabric exec`, `fabric cp`, `fabric port`), and federation Yamux peering are 100% unaffected.
2. **Zero Inbound Holes on Threads**: Threads maintain strictly outbound TLS connections to `fabric-server`. Mobile device traffic reaches threads without threads exposing ports.
3. **Cross-Platform Client Access**: Zero custom app development needed on mobile/TV platforms; works with official WireGuard client software on iOS, iPadOS, Android, tvOS, macOS, and Windows.
