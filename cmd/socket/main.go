package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"fabric/internal/protocol"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type NodeState struct {
	Conn     *websocket.Conn
	Metadata protocol.NodeMetadata
}

var (
	nodes     = make(map[string]*NodeState)
	nodesLock sync.RWMutex

	cliConns     = make(map[string]*websocket.Conn) // sessionID -> CLI conn
	cliConnsLock sync.RWMutex
)

func main() {
	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	domainFlag := flag.String("domain", defaultDomain, "Domain for the DNS server")
	flag.Parse()

	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	go StartTCPProxy()
	go pingNodes()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Upgrade error:", err)
			return
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			conn.Close()
			return
		}

		var envelope map[string]interface{}
		if err := json.Unmarshal(message, &envelope); err != nil {
			conn.Close()
			return
		}

		envelopeType, _ := envelope["type"].(string)

		switch protocol.EnvelopeType(envelopeType) {
		case protocol.TypeHandshake:
			var hs protocol.Handshake
			json.Unmarshal(message, &hs)

			if hs.Token != token {
				log.Println("Unauthorized connection from:", hs.Hostname)
				conn.Close()
				return
			}

			log.Printf("Node connected successfully: %s\n", hs.Hostname)

			nodesLock.Lock()
			nodes[hs.Hostname] = &NodeState{
				Conn: conn,
				Metadata: protocol.NodeMetadata{
					ID:          hs.Hostname, // simplifiy ID for now
					Hostname:    hs.Hostname,
					Domain:      hs.Domain,
					OS:          hs.OS,
					Arch:        hs.Arch,
					Version:     hs.Version,
					RemoteIP:    r.RemoteAddr,
					Status:      "online",
					ConnectedAt: time.Now().UTC().Format(time.RFC3339),
					LastSeen:    time.Now().UTC().Format(time.RFC3339),
				},
			}
			nodesLock.Unlock()
			go broadcastNodeSync()

			proxyIP := ""
			if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				proxyIP = tcpAddr.IP.String()
			} else {
				proxyIP = "127.0.0.1" // Fallback
			}

			defer func() {
				nodesLock.Lock()
				delete(nodes, hs.Hostname)
				nodesLock.Unlock()
				go broadcastNodeSync()
				conn.Close()
			}()

			handleNodeMessages(conn, hs.Hostname, *domainFlag, proxyIP)

		case protocol.TypeCopyRequest:
			var req protocol.CopyRequest
			json.Unmarshal(message, &req)

			nodesLock.RLock()
			nodeState, ok := nodes[req.TargetHostname]
			nodesLock.RUnlock()

			if !ok {
				conn.Close()
				return
			}

			cliConnsLock.Lock()
			cliConns[req.TransferID] = conn
			cliConnsLock.Unlock()

			defer func() {
				cliConnsLock.Lock()
				delete(cliConns, req.TransferID)
				cliConnsLock.Unlock()
			}()

			nodeState.Conn.WriteJSON(req)
			handleCLIMessages(conn, nodeState.Conn)
		case protocol.TypeExecRequest:
			var req protocol.ExecRequest
			json.Unmarshal(message, &req)

			log.Printf("CLI requested exec on %s: %s\n", req.TargetHostname, req.Command)

			nodesLock.RLock()
			nodeState, ok := nodes[req.TargetHostname]
			nodesLock.RUnlock()

			if !ok {
				log.Println("Target node not found:", req.TargetHostname)
				conn.Close()
				return
			}

			cliConnsLock.Lock()
			cliConns[req.SessionID] = conn
			cliConnsLock.Unlock()

			defer func() {
				cliConnsLock.Lock()
				delete(cliConns, req.SessionID)
				cliConnsLock.Unlock()
				conn.Close()
			}()

			err = nodeState.Conn.WriteJSON(req)
			if err != nil {
				log.Println("Error forwarding exec_request to node:", err)
				return
			}

			handleCLIMessages(conn, nodeState.Conn)
		case protocol.TypeProxyStream:
			var stream protocol.ProxyStream
			json.Unmarshal(message, &stream)

			// Route from CLI to Node
			nodesLock.RLock()
			var targetNode *NodeState
			for _, n := range nodes {
				targetNode = n
				break
			}
			nodesLock.RUnlock()

			if targetNode != nil {
				targetNode.Conn.WriteJSON(stream)
			}
		default:
			conn.Close()
		}
	})

	authenticate := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}

	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "1.0.0",
		})
	})

	http.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}

		nodesLock.RLock()
		defer nodesLock.RUnlock()

		var list []protocol.NodeMetadata
		for _, state := range nodes {
			list = append(list, state.Metadata)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	http.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			return
		}

		hostname := r.URL.Path[len("/nodes/"):]

		nodesLock.RLock()
		defer nodesLock.RUnlock()

		state, ok := nodes[hostname]
		if !ok {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state.Metadata)
	})

	log.Println("Socket listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func pingNodes() {
	for {
		time.Sleep(5 * time.Second)
		nodesLock.RLock()
		for _, state := range nodes {
			state.Metadata.LastSeen = time.Now().UTC().Format(time.RFC3339)
			state.Conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second))
		}
		nodesLock.RUnlock()
	}
}

func handleNodeMessages(conn *websocket.Conn, hostname string, domain string, proxyIP string) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var envelope map[string]interface{}
		json.Unmarshal(message, &envelope)

		envelopeType, _ := envelope["type"].(string)
		switch protocol.EnvelopeType(envelopeType) {
		case protocol.TypeDNSQuery:
			var query protocol.DNSQuery
			json.Unmarshal(message, &query)

			resp := ProcessDNSQuery(query, domain, proxyIP)
			conn.WriteJSON(resp)

		case protocol.TypeExecStream:
			var stream protocol.ExecStream
			json.Unmarshal(message, &stream)

			cliConnsLock.RLock()
			cliConn, ok := cliConns[stream.SessionID]
			cliConnsLock.RUnlock()

			if ok {
				cliConn.WriteJSON(stream)
			}
		case protocol.TypeCopyStream:
			var stream protocol.CopyStream
			json.Unmarshal(message, &stream)

			cliConnsLock.RLock()
			cliConn, ok := cliConns[stream.TransferID]
			cliConnsLock.RUnlock()

			if ok {
				cliConn.WriteJSON(stream)
			}
		case protocol.TypeProxyStream:
			var stream protocol.ProxyStream
			json.Unmarshal(message, &stream)

			proxyConnsLock.RLock()
			proxyConn, ok := proxyConns[stream.ConnID]
			proxyConnsLock.RUnlock()

			if ok {
				if stream.IsClosed {
					proxyConn.Close()
					proxyConnsLock.Lock()
					delete(proxyConns, stream.ConnID)
					proxyConnsLock.Unlock()
				} else {
					data, _ := base64.StdEncoding.DecodeString(stream.Data)
					proxyConn.Write(data)
				}
			}
		}
	}
}

func handleCLIMessages(cliConn *websocket.Conn, nodeConn *websocket.Conn) {
	for {
		_, message, err := cliConn.ReadMessage()
		if err != nil {
			break
		}

		var envelope map[string]interface{}
		json.Unmarshal(message, &envelope)

		envelopeType, _ := envelope["type"].(string)
		if protocol.EnvelopeType(envelopeType) == protocol.TypeExecStream || protocol.EnvelopeType(envelopeType) == protocol.TypeCopyStream {
			nodeConn.WriteMessage(websocket.TextMessage, message)
		}
	}
}

func broadcastNodeSync() {
	nodesLock.RLock()
	defer nodesLock.RUnlock()

	var list []protocol.NodeMetadata
	for _, state := range nodes {
		list = append(list, state.Metadata)
	}

	syncMsg := protocol.NodeSync{
		Type:  protocol.TypeNodeSync,
		Nodes: list,
	}

	for _, state := range nodes {
		state.Conn.WriteJSON(syncMsg)
	}
}
