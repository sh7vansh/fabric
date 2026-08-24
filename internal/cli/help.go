package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	topicArchitectureCmd = &cobra.Command{
		Use:     "architecture",
		Short:   "Guide to Fabric's Socket-Node-CLI topology and relay architecture",
		GroupID: "topics",
		Long: `Fabric Architecture Overview:

Fabric uses a hub-and-spoke mesh topology designed to orchestrate remote
hosts securely behind firewalls and NATs without requiring inbound ports.

Components:
  1. fabric-socket (Relay & Control Plane)
     - Central hub maintaining active WebSocket connections with nodes and CLIs.
     - Embeds an RFC 1035 Mesh DNS server responding to queries for the mesh domain.
     - Routes TCP proxy traffic and synchronizes cluster node state.

  2. fabric-node (Host Agent Daemon)
     - Runs as a persistent agent on managed machines.
     - Initiates OUTBOUND-ONLY WebSocket connections to fabric-socket.
     - Spawns PTY sessions, streams tar archives for file copies, and manages local OS DNS.

  3. fabric (Operator CLI)
     - Connects to fabric-socket over WebSocket to interact with any registered node.
     - Executes commands (exec), transfers files (cp), inspects nodes, forwards ports,
       and discovers/provisions new machines (stitch).

Communication Flow:
  [ fabric CLI ] ----WebSocket----> [ fabric-socket ] <----WebSocket---- [ fabric-node ]
   (Operator)                         (Relay & DNS)                       (Target Host)
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}

	topicNetworkingCmd = &cobra.Command{
		Use:     "networking",
		Short:   "Guide to Mesh DNS (.mesh), TCP Proxying, and Outbound Tunnels",
		GroupID: "topics",
		Long: `Fabric Networking & Mesh DNS:

1. Outbound-Only WebSockets:
   Nodes connect outbound to the Socket relay. Firewalls on target hosts do
   not require inbound open ports or port-forwarding rules.

2. Mesh DNS (.mesh):
   - fabric-socket embeds a DNS server handling queries for the mesh domain
     (default: fabric.mesh or *.fabric.mesh).
   - Node agent configures local system routing (via systemd-resolved or /etc/hosts)
     so applications on any node can resolve fellow nodes by hostname:
       curl http://api-server.fabric.mesh/
   - DNS state is deterministically cleaned up on node shutdown or disconnect.

3. TCP Port Forwarding:
   - Use 'fabric port <node> <local_port:remote_port>' to bridge local TCP ports
     directly to services running on remote nodes through the multiplexed WebSocket stream.
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}

	topicSecurityCmd = &cobra.Command{
		Use:     "security",
		Short:   "Guide to authentication tokens, firewall safety, and invariants",
		GroupID: "topics",
		Long: `Fabric Security & Operational Invariants:

1. Zero Inbound Exposure:
   Nodes maintain persistent outbound tunnels. Attack surface on target machines
   is minimized since no listening public ports are opened for node control.

2. Pre-Shared Token Authentication:
   - All connections (both nodes and CLIs) authenticate with FABRIC_TOKEN during
     the WebSocket handshake (TypeHandshake).
   - Unauthorized handshakes are rejected immediately before relay registration.

3. Safe Streaming & Process Teardown:
   - Command streams and file transfers operate over chunked Base64 buffers.
   - PTY allocations and process subprocesses terminate deterministically when
     the controlling CLI session or WebSocket closes.
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}

	topicWorkflowsCmd = &cobra.Command{
		Use:     "workflows",
		Short:   "Common CLI recipes and operational walkthroughs",
		GroupID: "topics",
		Long: `Common Fabric CLI Recipes:

1. Quick Node Inspection:
   $ fabric node ls
   $ fabric node inspect worker-1

2. Interactive Shell & PTY:
   $ fabric exec -i -t worker-1 /bin/bash

3. Running Background / Detached Commands:
   $ fabric exec -d worker-1 /opt/app/start.sh

4. File & Directory Transfers:
   # Upload directory to remote host
   $ fabric cp ./dist/ worker-1:/var/www/html/

   # Download remote log file
   $ fabric cp worker-1:/var/log/app.log ./app.log

5. Port Forwarding:
   # Forward local port 8080 to remote node's port 80
   $ fabric port worker-1 8080:80

6. Cluster Provisioning:
   # Stitch a single SSH host
   $ fabric stitch root@192.168.1.50

   # Discover & batch stitch all reachable hosts in subnet
   $ fabric stitch discover 192.168.1.0/24
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}
)

func init() {
	rootCmd.AddCommand(topicArchitectureCmd)
	rootCmd.AddCommand(topicNetworkingCmd)
	rootCmd.AddCommand(topicSecurityCmd)
	rootCmd.AddCommand(topicWorkflowsCmd)
}

func formatExamples(examples []string) string {
	var sb strings.Builder
	for _, ex := range examples {
		sb.WriteString("  " + ex + "\n")
	}
	return sb.String()
}
