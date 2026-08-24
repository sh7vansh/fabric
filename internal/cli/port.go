package cli

import (
	"encoding/base64"
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

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

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to bind local port %d: %w", localPort, err)
	}
	defer ln.Close()

	fmt.Printf("Forwarding 127.0.0.1:%d -> %s:%d (Ctrl+C to stop)...\n", localPort, nodeName, remotePort)

	var activeConns = make(map[string]net.Conn)
	var activeLock sync.RWMutex
	connIDCounter := 0
	var counterLock sync.Mutex

	// Read ProxyStreams from WebSocket back to local TCP connections
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			var env map[string]interface{}
			if err := json.Unmarshal(msg, &env); err != nil {
				continue
			}

			if env["type"] == string(protocol.TypeProxyStream) {
				var stream protocol.ProxyStream
				if err := json.Unmarshal(msg, &stream); err != nil {
					continue
				}

				activeLock.RLock()
				c, ok := activeConns[stream.ConnID]
				activeLock.RUnlock()

				if ok {
					if stream.IsClosed {
						c.Close()
						activeLock.Lock()
						delete(activeConns, stream.ConnID)
						activeLock.Unlock()
					} else {
						data, _ := base64.StdEncoding.DecodeString(stream.Data)
						c.Write(data)
					}
				}
			}
		}
	}()

	for {
		localConn, err := ln.Accept()
		if err != nil {
			return err
		}

		counterLock.Lock()
		connIDCounter++
		connID := fmt.Sprintf("port-fwd-%d", connIDCounter)
		counterLock.Unlock()

		activeLock.Lock()
		activeConns[connID] = localConn
		activeLock.Unlock()

		go func(c net.Conn, id string) {
			defer func() {
				c.Close()
				activeLock.Lock()
				delete(activeConns, id)
				activeLock.Unlock()
			}()

			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					conn.WriteJSON(protocol.ProxyStream{
						Type:       protocol.TypeProxyStream,
						ConnID:     id,
						TargetPort: remotePort,
						Data:       base64.StdEncoding.EncodeToString(buf[:n]),
						IsClosed:   false,
					})
				}
				if err != nil {
					if err != io.EOF {
						log.Printf("local connection read error: %v", err)
					}
					conn.WriteJSON(protocol.ProxyStream{
						Type:       protocol.TypeProxyStream,
						ConnID:     id,
						TargetPort: remotePort,
						IsClosed:   true,
					})
					break
				}
			}
		}(localConn, connID)
	}
}
