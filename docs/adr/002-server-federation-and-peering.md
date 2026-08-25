# ADR 002: Fabric Multi-Server Federation & Peering

## Status
**Accepted** (Ratified: 2026-08-26)

---

## Context & Motivation

Fabric initially operated as a single-gateway platform: all `fabric-agent` daemons connected to a single central `fabric-server` instance. While this architecture is exceptionally lightweight and simple for single-cluster environments, modern deployments require bridging threads across disparate networks, public cloud regions, and private on-premise infrastructure without compromising Fabric's core zero-inbound-firewall-hole invariant.

To support global, cross-cloud, and edge deployments, Fabric requires a multi-server federation architecture capable of scaling from two local servers to hundreds of globally distributed gateways with seamless operator execution, file transfer, and DNS name resolution.

---

## Decision

### 1. Topology: 2-Tier Hybrid Federated Mesh

Fabric adopts a **2-Tier Hybrid Federated Architecture**:

1. **Core Gateways (Public Cloud / Static IP)**:
   - Deployed on accessible infrastructure (e.g. AWS, GCP, Hetzner, or static public IPs).
   - Core Gateways establish symmetric, bidirectional Yamux-over-TLS/WebSocket peering connections with each other, forming a **Federated Core Mesh**.
   - In symmetric peering, if both servers attempt to connect simultaneously, a lexicographical tie-breaker on `GatewayID` deduplicates redundant links.

2. **Leaf Gateways (Edge / Private VPC / NAT)**:
   - Deployed on firewalled edge networks, private VPCs, or labs with zero open inbound ports.
   - Leaf Gateways initiate persistent outbound Yamux-over-TLS connections to a designated Core Gateway (`fabric-server --leaf-of wss://core-hub.fabric.io`).
   - Because Yamux is bidirectional, the Core Gateway can immediately route execution streams downward into the edge network.

```text
               PUBLIC CLOUD / STATIC IP                      PUBLIC CLOUD / STATIC IP
        ┌────────────────────────────────────┐        ┌────────────────────────────────────┐
        │       fabric-server (US-East)      │◄──────►│       fabric-server (EU-West)      │
        │           ID: `gw-us-east`         │  Yamux │           ID: `gw-eu-west`         │
        └────────────────────────────────────┘  Mesh  └────────────────────────────────────┘
             ▲                         ▲                            ▲
             │ Outbound                │ Outbound                   │ Outbound
             │ Thread Tunnel           │ Leaf Tunnel                │ Thread Tunnel
             │                         │ (NAT Reverse Tunnel)       │
    ┌────────────────┐       ┌──────────────────────┐      ┌────────────────┐
    │  fabric-agent  │       │ fabric-server (Edge) │      │  fabric-agent  │
    │  thread: `db1` │       │   ID: `gw-onprem`    │      │ thread: `web1` │
    └────────────────┘       └──────────────────────┘      └────────────────┘
      AWS US-East                  FIREWALLED LAB             Hetzner Europe
                                   (Behind strict NAT)
                                       ▲
                                       │ Outbound Thread Tunnel
                                       │
                             ┌───────────────────┐
                             │   fabric-agent    │
                             │ thread: `sensor1` │
                             └───────────────────┘
```

---

### 2. Security & Trust: Mutual TLS (mTLS) with Shared Federation CA

To achieve $O(1)$ configuration scaling across arbitrary gateway counts:

1. **Federation Root CA**:
   - All federated gateways validate peer connections against a shared Federation Root CA (`--federation-ca /path/to/ca.crt`).
   - Each gateway is provisioned with an x509 leaf certificate where its unique `GatewayID` is embedded in the Subject Common Name (`CN=gw-id.fabric`) and SANs.
2. **Dynamic Peer Verification**:
   - At TLS 1.3 handshake time, both gateways verify each other's certificates against the trusted Federation CA pool.
   - No pairwise pre-shared keys or static fingerprint lists are required, allowing seamless addition and zero-downtime key rotation of gateways.
3. **Application Handshake (`TypeGatewayHello`)**:
   - Following TLS upgrade to Yamux, gateways exchange a `TypeGatewayHello` envelope containing `GatewayID`, `Region`, and `Capabilities` (`["exec", "cp", "proxy", "dns"]`).

---

### 3. Stream Routing: Hop-by-Hop Yamux Multiplexing

Cross-server stream execution (`exec`, `cp`, `port`) operates over existing peer Yamux connections:

1. **Multiplexed Virtual Channels**:
   - Gateways maintain a single persistent TCP/TLS connection between them, multiplexing hundreds of virtual streams via Yamux.
2. **Transparent Ingress Forwarding**:
   - When an operator CLI sends a request targeting a remote thread (e.g. `sensor1.gw-onprem`), the ingress gateway opens a new Yamux stream on the peer connection to `gw-onprem`.
   - The remote gateway accepts the stream, opens a stream to the local `sensor1` agent, and transparently pipes bidirectional bytes (`io.Copy`).
3. **Loop Prevention & Telemetry**:
   - Routed frames carry a `Path: []string{"gw-us-east", "gw-onprem"}` header and hop counter (`Hops`) to detect and discard circular routing loops.

---

### 4. Naming & Federated DNS Wire Resolution

1. **Hierarchical Fully Qualified Thread Names (FQTN)**:
   - Federated threads are uniquely addressed via: `<thread-name>.<gateway-id>.fabric` (e.g. `web-1.eu-west.fabric`, `db-1.us-east.fabric`).
   - Local shortnames (`web-1` or `web-1.fabric`) remain supported for local cluster operations.
2. **Federated DNS Resolution**:
   - Fabric's embedded DNS server (`internal/meshdns`) resolves FQTNs for remote threads to the **ingress gateway's local proxy port**.
   - Outbound TCP connections from local threads/clients to that port are automatically tunneled across the cross-server Yamux link, providing zero-configuration transparent mesh networking.

---

### 5. Operator CLI Hierarchy (`fabric peer`)

```text
fabric peer
├── ls                                      # List connected server peers, regions, RTT, and thread counts
├── add <endpoint>                          # Connect to a remote gateway peer
├── rm <gateway-id>                         # Disconnect and remove a gateway peer
└── inspect <gateway-id>                    # Detailed telemetry and routing table for a peer
```

- `fabric ps`: Lists threads across all peered clusters, displaying their hosting `GATEWAY` ID.
- `fabric exec <thread>.<gateway-id> [cmd...]`: Executes commands across federated gateways.
- `fabric cp <src> <thread>.<gateway-id>:<dst>`: Streams Tar archives across federated gateways.
- `fabric port <thread>.<gateway-id> [local:remote]`: Bridges TCP ports across federated gateways.

---

## Consequences

- **Scalability**: Enables Fabric networks to span across multiple clouds, on-premise datacenters, and edge devices with $O(1)$ CA configuration.
- **Firewall Simplicity**: Edge and private servers require zero open inbound ports, using outbound Leaf reverse tunnels.
- **Operator Consistency**: Preserves Fabric's core design principle: actions stay obvious (`exec`, `cp`, `port`, `ps`), while hierarchical naming prevents naming collisions.
