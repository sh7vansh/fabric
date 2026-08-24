package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"crypto/tls"
	"fmt"
	"fabric/internal/protocol"
	"fabric/internal/tlsengine"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type NodeState struct {
	Mux      *protocol.StreamMultiplexer
	Metadata protocol.NodeMetadata
}

var (
	nodes     = make(map[string]*NodeState)
	nodesLock sync.RWMutex
)

func main() {
	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	domainFlag := flag.String("domain", defaultDomain, "Domain for the DNS server")
	publicDomainFlag := flag.String("public-domain", os.Getenv("FABRIC_PUBLIC_DOMAIN"), "Public domain for ACME TLS certificates (e.g. example.com)")
	acmeEmailFlag := flag.String("acme-email", os.Getenv("FABRIC_ACME_EMAIL"), "Email address for Let's Encrypt ACME registration")
	acmeStagingFlag := flag.Bool("acme-staging", os.Getenv("FABRIC_ACME_STAGING") == "true", "Use Let's Encrypt staging environment")
	tlsPortFlag := flag.Int("tls-port", 443, "Port for HTTPS/WSS TLS listener")
	httpPortFlag := flag.Int("http-port", 80, "Port for HTTP / ACME HTTP-01 challenge listener")
	caDirFlag := flag.String("ca-dir", "", "Directory to store internal Root CA")
	flag.Parse()

	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	// Initialize Dual-Mode TLS Engine (Internal CA + ACME Autocert)
	tlsEng, err := tlsengine.New(tlsengine.Config{
		CADir:        *caDirFlag,
		MeshDomain:   *domainFlag,
		PublicDomain: *publicDomainFlag,
		ACMEEmail:    *acmeEmailFlag,
		ACMEStaging:  *acmeStagingFlag,
		ActiveNodes: func() []string {
			nodesLock.RLock()
			defer nodesLock.RUnlock()
			var list []string
			for k := range nodes {
				list = append(list, k)
			}
			return list
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize TLS engine: %v", err)
	}

	// Start Port 80 HTTP Server (ACME Challenges + 301 HTTPS Redirects)
	go func() {
		httpAddr := fmt.Sprintf(":%d", *httpPortFlag)
		srv := &http.Server{
			Addr:    httpAddr,
			Handler: tlsEng.HTTPSRedirectHandler(*tlsPortFlag),
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP] Port %d listener info (run with sudo for port 80): %v", *httpPortFlag, err)
		}
	}()

	// Start Port 443 HTTPS / WSS Server (Dynamic Dual-Mode SNI)
	go func() {
		tlsAddr := fmt.Sprintf(":%d", *tlsPortFlag)
		tlsLn, err := net.Listen("tcp", tlsAddr)
		if err != nil {
			log.Printf("[TLS] Port %d listener info (run with sudo for port 443): %v", *tlsPortFlag, err)
			return
		}
		defer tlsLn.Close()
		log.Printf("[TLS] Socket TLS listening on %s (HTTPS / WSS with Dual-Mode SNI)", tlsAddr)

		secureSrv := &http.Server{
			Handler: http.DefaultServeMux,
		}
		secureLn := tls.NewListener(tlsLn, tlsEng.TLSConfig())
		if err := secureSrv.Serve(secureLn); err != nil && err != http.ErrServerClosed {
			log.Printf("[TLS] Server error on %s: %v", tlsAddr, err)
		}
	}()

	go pingNodes()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Upgrade error:", err)
			return
		}

		mux, err := protocol.NewStreamMultiplexer(conn, true)
		if err != nil {
			conn.Close()
			return
		}

		router := protocol.NewRouter(mux.Session)

		proxyIP := ""
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			proxyIP = tcpAddr.IP.String()
		} else {
			proxyIP = "127.0.0.1"
		}

		router.HandleFunc(string(protocol.TypeHandshake), func(stream net.Conn, env []byte) {
			defer stream.Close()
			var hs protocol.Handshake
			json.Unmarshal(env, &hs)

			if hs.Token != token {
				log.Println("Unauthorized connection from:", hs.Hostname)
				conn.Close()
				return
			}

			log.Printf("Node connected successfully: %s\n", hs.Hostname)

			nodesLock.Lock()
			nodes[hs.Hostname] = &NodeState{
				Mux: mux,
				Metadata: protocol.NodeMetadata{
					ID:          hs.Hostname,
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

			go func() {
				// We don't need handleNodeMessages anymore since router.Accept() will handle new streams.
				// However, if the mux fails, we should remove the node.
				<-mux.Session.CloseChan()
				nodesLock.Lock()
				delete(nodes, hs.Hostname)
				nodesLock.Unlock()
				go broadcastNodeSync()
				conn.Close()
			}()
		})

		router.HandleFunc(string(protocol.TypeDNSQuery), func(stream net.Conn, env []byte) {
			defer stream.Close()
			var query protocol.DNSQuery
			json.Unmarshal(env, &query)

			resp := ProcessDNSQuery(query, *domainFlag, proxyIP)
			b, _ := json.Marshal(resp)
			
			// We can respond directly on the same stream since DNS is request/response, 
			// but we can also open a new stream. To keep it simple, we just write to the same stream.
			// Actually the client expects it on `DNSResponse` handler.
			outStream, err := mux.Session.Open()
			if err == nil {
				outStream.Write(b)
				outStream.Close()
			}
		})

		// For CLI -> Node routing requests (Exec, Copy, Proxy)
		router.HandleFunc(string(protocol.TypeExecRequest), func(stream net.Conn, env []byte) {
			var req protocol.ExecRequest
			json.Unmarshal(env, &req)

			log.Printf("CLI requested exec on %s: %s\n", req.TargetHostname, req.Command)

			nodesLock.RLock()
			nodeState, ok := nodes[req.TargetHostname]
			nodesLock.RUnlock()

			if !ok {
				log.Println("Target node not found:", req.TargetHostname)
				stream.Close()
				return
			}

			targetStream, err := nodeState.Mux.Session.Open()
			if err != nil {
				stream.Close()
				return
			}

			targetStream.Write(env)
			go protocol.Proxy(stream, targetStream)
		})

		router.HandleFunc(string(protocol.TypeCopyRequest), func(stream net.Conn, env []byte) {
			var req protocol.CopyRequest
			json.Unmarshal(env, &req)

			nodesLock.RLock()
			nodeState, ok := nodes[req.TargetHostname]
			nodesLock.RUnlock()

			if !ok {
				stream.Close()
				return
			}

			targetStream, err := nodeState.Mux.Session.Open()
			if err != nil {
				stream.Close()
				return
			}

			targetStream.Write(env)
			go protocol.Proxy(stream, targetStream)
		})

		router.HandleFunc(string(protocol.TypeProxyRequest), func(stream net.Conn, env []byte) {
			var req protocol.ProxyRequest
			json.Unmarshal(env, &req)

			nodesLock.RLock()
			var targetNode *NodeState
			if req.TargetHostname != "" {
				targetNode = nodes[req.TargetHostname]
			} else {
				for _, n := range nodes {
					targetNode = n
					break
				}
			}
			nodesLock.RUnlock()

			if targetNode != nil {
				targetStream, err := targetNode.Mux.Session.Open()
				if err == nil {
					targetStream.Write(env)
					go protocol.Proxy(stream, targetStream)
				} else {
					stream.Close()
				}
			} else {
				stream.Close()
			}
		})

		router.Accept()
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
			// Yamux does its own keepalive, we can rely on that or send a custom ping.
			// For now just update LastSeen.
		}
		nodesLock.RUnlock()
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

	b, _ := json.Marshal(syncMsg)

	for _, state := range nodes {
		stream, err := state.Mux.Session.Open()
		if err == nil {
			stream.Write(b)
			stream.Close()
		}
	}
}
