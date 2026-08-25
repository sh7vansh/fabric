package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	topicArchitectureCmd = &cobra.Command{
		Use:     "architecture",
		Short:   "Guide to Fabric's Server-Thread-CLI topology and mesh architecture",
		GroupID: "topics",
		Long: `Fabric Architecture Overview:

Fabric uses a hub-and-spoke mesh topology designed to orchestrate remote
hosts securely behind firewalls and NATs without requiring inbound ports.

Components:
  1. fabric-server (Fabric Server & Control Plane)
     - Central hub maintaining active WebSocket connections with threads and CLIs.
     - Embeds an RFC 1035 Fabric DNS server responding to queries for the mesh domain.
     - Routes TCP proxy traffic and synchronizes cluster thread state.

  2. fabric-agent (Host Agent Daemon)
     - Runs as a persistent agent on managed machines (threads).
     - Initiates OUTBOUND-ONLY WebSocket connections to fabric-server.
     - Spawns PTY sessions, streams tar archives for file copies, and manages local OS DNS.

  3. fabric (Operator CLI)
     - Connects to fabric-server over WebSocket to interact with any registered thread.
     - Executes commands (exec), transfers files (cp), inspects threads (thread/ps), forwards ports (port),
       and discovers/provisions new machines (stitch).

Communication Flow:
  [ fabric CLI ] ----WebSocket----> [ fabric-server ] <----WebSocket---- [ fabric-agent ]
   (Operator)                         (Server & DNS)                       (Managed Thread)
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}

	topicNetworkingCmd = &cobra.Command{
		Use:     "networking",
		Short:   "Guide to Fabric DNS (.mesh), TCP Proxying, and Outbound Tunnels",
		GroupID: "topics",
		Long: `Fabric Networking & Fabric DNS:

1. Outbound-Only WebSockets:
   Threads connect outbound to the central Fabric server. Firewalls on target hosts
   do not require inbound open ports or port-forwarding rules.

2. Fabric DNS (.mesh):
   - fabric-server embeds a DNS server handling queries for the mesh domain
     (default: fabric.mesh or *.fabric.mesh).
   - Agent daemons configure local system routing (via systemd-resolved or /etc/hosts)
     so applications on any thread can resolve fellow threads by hostname:
       curl http://api-server.fabric.mesh/
   - DNS state is deterministically cleaned up on agent shutdown or disconnect.

3. TCP Port Forwarding:
   - Use 'fabric port <thread> <local_port:remote_port>' to bridge local TCP ports
     directly to services running on remote threads through the multiplexed WebSocket stream.
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
   Threads maintain persistent outbound tunnels. Attack surface on target machines
   is minimized since no listening public ports are opened for thread control.

2. Pre-Shared Token Authentication:
   - All connections (both threads and CLIs) authenticate with FABRIC_TOKEN during
     the WebSocket handshake.
   - Unauthorized handshakes are rejected immediately before relay registration.

3. Safe Streaming & Process Teardown:
   - Command streams and file transfers operate over chunked Base64 buffers.
   - PTY allocations and subprocesses terminate deterministically when
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

1. Thread Listing & Inspection:
   $ fabric ps
   $ fabric thread ls
   $ fabric thread inspect worker-1

2. Interactive Shell & PTY:
   $ fabric exec -i -t worker-1 /bin/bash

3. Running Background / Detached Commands:
   $ fabric exec -d worker-1 /opt/app/start.sh

4. Fleet Execution Across Tags:
   $ fabric exec --tag web uptime

5. File & Directory Transfers:
   # Upload directory to remote thread
   $ fabric cp ./dist/ worker-1:/var/www/html/

   # Download remote log file
   $ fabric cp worker-1:/var/log/app.log ./app.log

6. Port Forwarding:
   # Forward local port 8080 to remote thread's port 80
   $ fabric port worker-1 8080:80

7. Machine Onboarding & Subnet Scanning:
   # Stitch a single SSH host as a thread
   $ fabric stitch root@192.168.1.50

   # Discover & batch stitch all reachable hosts in subnet
   $ fabric stitch 192.168.1.0/24
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}

	topicThreadsCmd = &cobra.Command{
		Use:     "threads",
		Short:   "Guide to Thread lifecycle, tag filtering, and telemetry",
		GroupID: "topics",
		Long: `Fabric Thread Management:

A Thread is any managed host or compute environment running the 'fabric-agent'
daemon connected to the central Fabric server.

1. Listing Active Threads:
   $ fabric ps
   $ fabric thread ls
   $ fabric thread ls -q                # Names only
   $ fabric thread ls --format json     # Full JSON metadata

2. Filtering by Tags:
   $ fabric thread ls -l prod
   $ fabric thread ls -l web

3. Inspecting Thread Telemetry:
   $ fabric thread inspect worker-1 worker-2
`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(cmd.Long)
		},
	}

	topicStitchGuideCmd = &cobra.Command{
		Use:     "stitch-guide",
		Short:   "Guide to SSH machine onboarding and polymorphic subnet discovery",
		GroupID: "topics",
		Long: `Fabric Stitch & Provisioning Guide:

'fabric stitch' automates bootstrapping remote machines into the Fabric mesh over SSH.

1. Polymorphic Target Resolution:
   - Single Host: 'fabric stitch user@192.168.1.50'
     Connects over SSH, installs fabric-agent, and brings the machine online as a thread.
   - CIDR Subnet: 'fabric stitch 192.168.1.0/24'
     Scans the entire subnet for open SSH ports and prompts for interactive or batch onboarding.
   - Default Local Subnet: 'fabric stitch'
     Auto-detects the active local subnet and runs discovery scan.

2. Batch Mode:
   $ fabric stitch --batch --user ubuntu 10.0.0.0/24

3. Remote / Direct mTLS Mode:
   $ fabric stitch --remote --listen-port 8443 ubuntu@10.0.0.12
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
	rootCmd.AddCommand(topicThreadsCmd)
	rootCmd.AddCommand(topicStitchGuideCmd)
}
