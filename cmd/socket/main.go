package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
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

var (
	nodes     = make(map[string]*websocket.Conn)
	nodesLock sync.RWMutex

	cliConns     = make(map[string][]*websocket.Conn) // targetHostname -> CLI conns
	cliConnsLock sync.RWMutex
)

func main() {
	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	go StartDNSServer("127.0.0.1")
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
			nodes[hs.Hostname] = conn
			nodesLock.Unlock()

			defer func() {
				nodesLock.Lock()
				delete(nodes, hs.Hostname)
				nodesLock.Unlock()
				conn.Close()
			}()

			handleNodeMessages(conn, hs.Hostname)

		case protocol.TypeExecRequest:
			var req protocol.ExecRequest
			json.Unmarshal(message, &req)

			log.Printf("CLI requested exec on %s: %s\n", req.TargetHostname, req.Command)

			nodesLock.RLock()
			nodeConn, ok := nodes[req.TargetHostname]
			nodesLock.RUnlock()

			if !ok {
				log.Println("Target node not found:", req.TargetHostname)
				conn.Close()
				return
			}

			cliConnsLock.Lock()
			cliConns[req.TargetHostname] = append(cliConns[req.TargetHostname], conn)
			cliConnsLock.Unlock()

			defer func() {
				cliConnsLock.Lock()
				conns := cliConns[req.TargetHostname]
				for i, c := range conns {
					if c == conn {
						cliConns[req.TargetHostname] = append(conns[:i], conns[i+1:]...)
						break
					}
				}
				cliConnsLock.Unlock()
				conn.Close()
			}()

			err = nodeConn.WriteJSON(req)
			if err != nil {
				log.Println("Error forwarding exec_request to node:", err)
				return
			}

			handleCLIMessages(conn, nodeConn)
		default:
			conn.Close()
		}
	})

	log.Println("Socket listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func pingNodes() {
	for {
		time.Sleep(5 * time.Second)
		nodesLock.RLock()
		for _, conn := range nodes {
			conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second))
		}
		nodesLock.RUnlock()
	}
}

func handleNodeMessages(conn *websocket.Conn, hostname string) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var envelope map[string]interface{}
		json.Unmarshal(message, &envelope)

		envelopeType, _ := envelope["type"].(string)
		switch protocol.EnvelopeType(envelopeType) {
		case protocol.TypeExecStream:
			var stream protocol.ExecStream
			json.Unmarshal(message, &stream)

			cliConnsLock.RLock()
			conns := cliConns[hostname]
			cliConnsLock.RUnlock()

			for _, cliConn := range conns {
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
		if protocol.EnvelopeType(envelopeType) == protocol.TypeExecStream {
			nodeConn.WriteMessage(websocket.TextMessage, message)
		}
	}
}
