package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"fabric/internal/protocol"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var (
	nodes     = make(map[string]*websocket.Conn)
	nodesLock sync.RWMutex

	cliConns     = make(map[string]*websocket.Conn) // SessionID -> CLI conn
	cliConnsLock sync.RWMutex
)

func main() {
	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	go StartDNSServer("127.0.0.1")
	go StartHTTPProxy()

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

		var env map[string]interface{}
		if err := json.Unmarshal(message, &env); err != nil {
			conn.Close()
			return
		}

		msgType, _ := env["type"].(string)

		if msgType == "handshake" {
			var hs protocol.Handshake
			json.Unmarshal(message, &hs)

			if hs.Token != token {
				log.Println("Unauthorized connection from:", hs.Hostname)
				conn.Close()
				return
			}

			log.Printf("Node connected successfully: %s (%s/%s)\n", hs.Hostname, hs.OS, hs.Arch)

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

		} else if msgType == "exec_request" {
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
			cliConns[req.SessionID] = conn
			cliConnsLock.Unlock()

			defer func() {
				cliConnsLock.Lock()
				delete(cliConns, req.SessionID)
				cliConnsLock.Unlock()
				conn.Close()
			}()

			err = nodeConn.WriteJSON(req)
			if err != nil {
				log.Println("Error forwarding exec_request to node:", err)
				return
			}

			handleCLIMessages(conn, nodeConn)
		}
	})

	log.Println("Socket listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleNodeMessages(conn *websocket.Conn, hostname string) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var env map[string]interface{}
		json.Unmarshal(message, &env)

		msgType, _ := env["type"].(string)
		if msgType == "exec_stream" {
			var stream protocol.ExecStream
			json.Unmarshal(message, &stream)

			cliConnsLock.RLock()
			cliConn, ok := cliConns[stream.SessionID]
			cliConnsLock.RUnlock()

			if ok {
				cliConn.WriteJSON(stream)
			}
		} else if msgType == "proxy_stream" {
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

		var env map[string]interface{}
		json.Unmarshal(message, &env)

		msgType, _ := env["type"].(string)
		if msgType == "exec_stream" {
			// Forward stdin stream to node
			nodeConn.WriteMessage(websocket.TextMessage, message)
		}
	}
}
