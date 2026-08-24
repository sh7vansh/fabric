package main

import (
	"encoding/base64"
	"log"
	"net"
	"sync"

	"fabric/internal/protocol"

	"github.com/gorilla/websocket"
)

var (
	proxyConns     = make(map[string]net.Conn)
	proxyConnsLock sync.RWMutex
)

func handleProxyStream(c *websocket.Conn, stream protocol.ProxyStream) {
	proxyConnsLock.RLock()
	conn, ok := proxyConns[stream.ConnID]
	proxyConnsLock.RUnlock()

	if stream.IsClosed {
		if ok {
			conn.Close()
			proxyConnsLock.Lock()
			delete(proxyConns, stream.ConnID)
			proxyConnsLock.Unlock()
		}
		return
	}

	if !ok {
		// Connect to local service, assuming port 80 for this prototype
		var err error
		conn, err = net.Dial("tcp", "127.0.0.1:80")
		if err != nil {
			log.Println("Node proxy dial error:", err)
			c.WriteJSON(protocol.ProxyStream{
				Type:     "proxy_stream",
				ConnID:   stream.ConnID,
				Data:     "",
				IsClosed: true,
			})
			return
		}

		proxyConnsLock.Lock()
		proxyConns[stream.ConnID] = conn
		proxyConnsLock.Unlock()

		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					c.WriteJSON(protocol.ProxyStream{
						Type:     "proxy_stream",
						ConnID:   stream.ConnID,
						Data:     base64.StdEncoding.EncodeToString(buf[:n]),
						IsClosed: false,
					})
				}
				if err != nil {
					c.WriteJSON(protocol.ProxyStream{
						Type:     "proxy_stream",
						ConnID:   stream.ConnID,
						Data:     "",
						IsClosed: true,
					})
					proxyConnsLock.Lock()
					delete(proxyConns, stream.ConnID)
					proxyConnsLock.Unlock()
					conn.Close()
					break
				}
			}
		}()
	}

	data, _ := base64.StdEncoding.DecodeString(stream.Data)
	conn.Write(data)
}
