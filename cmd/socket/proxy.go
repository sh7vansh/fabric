package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"fabric/internal/protocol"
)

var (
	proxyConns     = make(map[string]net.Conn)
	proxyConnsLock sync.RWMutex
	connIDCounter  int
	connIDLock     sync.Mutex
)

func StartHTTPProxy() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if !strings.HasSuffix(host, ".fabric.mesh") {
			http.Error(w, "Invalid host", http.StatusBadRequest)
			return
		}

		nodeName := strings.TrimSuffix(host, ".fabric.mesh")
		
		nodesLock.RLock()
		nodeConn, ok := nodes[nodeName]
		nodesLock.RUnlock()

		if !ok {
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		connIDLock.Lock()
		connIDCounter++
		connID := fmt.Sprintf("conn-%d", connIDCounter)
		connIDLock.Unlock()

		proxyConnsLock.Lock()
		proxyConns[connID] = conn
		proxyConnsLock.Unlock()

		reqBytes := []byte(fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto))
		for k, vv := range r.Header {
			for _, v := range vv {
				reqBytes = append(reqBytes, []byte(fmt.Sprintf("%s: %s\r\n", k, v))...)
			}
		}
		reqBytes = append(reqBytes, []byte("\r\n")...)

		nodeConn.WriteJSON(protocol.ProxyStream{
			Type:     "proxy_stream",
			ConnID:   connID,
			Data:     base64.StdEncoding.EncodeToString(reqBytes),
			IsClosed: false,
		})

		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := bufrw.Read(buf)
				if n > 0 {
					nodeConn.WriteJSON(protocol.ProxyStream{
						Type:     "proxy_stream",
						ConnID:   connID,
						Data:     base64.StdEncoding.EncodeToString(buf[:n]),
						IsClosed: false,
					})
				}
				if err != nil {
					nodeConn.WriteJSON(protocol.ProxyStream{
						Type:     "proxy_stream",
						ConnID:   connID,
						Data:     "",
						IsClosed: true,
					})
					proxyConnsLock.Lock()
					delete(proxyConns, connID)
					proxyConnsLock.Unlock()
					conn.Close()
					break
				}
			}
		}()
	})

	log.Println("Starting HTTP Proxy on :80")
	go func() {
		// Use a new ServeMux for proxy to not conflict with ws on port 8080
		mux := http.NewServeMux()
		mux.HandleFunc("/", http.DefaultServeMux.ServeHTTP)
		err := http.ListenAndServe(":80", mux)
		if err != nil {
			log.Println("HTTP Proxy error:", err)
		}
	}()
}
