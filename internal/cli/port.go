package cli

import (
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	portCmd.RunE = runPort
}

func runPort(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric port NODE [LOCAL_PORT:REMOTE_PORT]")
	}

	nodeName := args[0]
	client := NewClient(GetConfig())

	if len(args) == 1 {
		// Inspection mode
		resp, err := client.DoHTTP("GET", "/nodes/"+nodeName, nil)
		if err != nil {
			return fmt.Errorf("error querying node %s: %w", nodeName, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			return fmt.Errorf("node not found: %s", nodeName)
		}

		var meta protocol.NodeMetadata
		if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
			return err
		}

		domain := meta.Domain
		if domain == "" {
			domain = "fabric.mesh"
		}
		fmt.Printf("80/tcp -> http://%s.%s:80\n", meta.Hostname, domain)
		return nil
	}

	// Forwarding tunnel mode: LOCAL:REMOTE
	portSpec := args[1]
	parts := strings.Split(portSpec, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid port specification %q, expected LOCAL:REMOTE (e.g. 8080:80)", portSpec)
	}

	localPort, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid local port: %w", err)
	}
	remotePort, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid remote port: %w", err)
	}

	conn, err := client.DialWebSocket()
	if err != nil {
		return fmt.Errorf("failed to dial socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return fmt.Errorf("multiplexer error: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to bind local port %d: %w", localPort, err)
	}
	defer ln.Close()

	fmt.Printf("Forwarding 127.0.0.1:%d -> %s:%d (Ctrl+C to stop)...\n", localPort, nodeName, remotePort)

	for {
		localConn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			defer c.Close()

			stream, err := mux.Session.Open()
			if err != nil {
				return
			}
			defer stream.Close()

			req := protocol.ProxyRequest{
				Type:           protocol.TypeProxyRequest,
				TargetHostname: nodeName,
				TargetPort:     remotePort,
			}
			b, _ := json.Marshal(req)
			stream.Write(b)

			go io.Copy(stream, c)
			io.Copy(c, stream)
		}(localConn)
	}
}
