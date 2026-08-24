package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"fabric/internal/meshdns"
	"fabric/internal/pki"
	"fabric/internal/protocol"

	"github.com/creack/pty"
)

func main() {
	defaultURL := os.Getenv("FABRIC_SOCKET_URL")
	if defaultURL == "" {
		defaultURL = os.Getenv("FABRIC_HOST")
	}
	if defaultURL == "" {
		defaultURL = "ws://localhost:8080/ws"
	}

	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	serverURL := flag.String("url", defaultURL, "Socket URL (ws:// or wss://)")
	domainFlag := flag.String("domain", defaultDomain, "Domain to register with the mesh")
	caCertFlag := flag.String("ca-cert", os.Getenv("FABRIC_CA_CERT"), "Path to custom Root CA certificate")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
	}

	u, err := pki.NormalizeURL(*serverURL)
	if err != nil {
		log.Fatal(err)
	}

	dnsMgr := meshdns.NewSystemDNSManager(*domainFlag)
	if err := dnsMgr.Start(); err != nil {
		log.Fatalf("Failed to start DNS manager: %v", err)
	}
	defer dnsMgr.Teardown()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("Shutting down... Reverting OS DNS configuration.")
		dnsMgr.Teardown()
		os.Exit(0)
	}()

	hostname, _ := os.Hostname()
	sessionID := fmt.Sprintf("node-%s-%d", hostname, time.Now().UnixNano())

	for {
		c := ConnectWithRetry(*u, token, *caCertFlag)

		mux, err := protocol.NewStreamMultiplexer(c, false)
		dnsMgr.SetMultiplexer(mux)
		if err != nil {
			log.Println("Multiplexer error:", err)
			c.Close()
			continue
		}

		stream, err := mux.Session.Open()
		if err != nil {
			log.Println("Open stream error:", err)
			c.Close()
			continue
		}

		hs := protocol.Handshake{
			Type:      protocol.TypeHandshake,
			SessionID: sessionID,
			Hostname:  hostname,
			Domain:    *domainFlag,
			Token:     token,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			Version:   "1.0.0",
		}

		b, _ := json.Marshal(hs)
		stream.Write(b)
		stream.Close() // Handshake stream is transient

		log.Println("Handshake sent successfully.")

		router := protocol.NewRouter(mux.Session)

		router.HandleFunc(string(protocol.TypeNodeSync), func(s net.Conn, env []byte) {
			defer s.Close()
			var syncMsg protocol.NodeSync
			json.Unmarshal(env, &syncMsg)
			dnsMgr.SyncNodes(syncMsg.Nodes, *serverURL)
		})

		router.HandleFunc(string(protocol.TypeDNSResponse), func(s net.Conn, env []byte) {
			defer s.Close()
			var resp protocol.DNSResponse
			json.Unmarshal(env, &resp)
			dnsMgr.HandleDNSResponse(resp)
		})

		router.HandleFunc(string(protocol.TypeExecRequest), handleExec)
		router.HandleFunc(string(protocol.TypeCopyRequest), handleCopyRequest)
		router.HandleFunc(string(protocol.TypeProxyRequest), handleProxyRequest)

		if err := router.Accept(); err != nil {
			log.Println("Router accept error:", err)
		}

		c.Close()
		log.Println("Connection closed, reconnecting...")
	}
}

func handleExec(stream net.Conn, env []byte) {
	defer stream.Close()

	var req protocol.ExecRequest
	if err := json.Unmarshal(env, &req); err != nil {
		return
	}

	command := req.Command
	if req.User != "" {
		command = fmt.Sprintf("su - %s -c %q", req.User, req.Command)
	}
	cmd := exec.Command("sh", "-c", command)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	if len(req.Env) > 0 {
		cmd.Env = append(os.Environ(), req.Env...)
	}

	if req.Detached {
		if err := cmd.Start(); err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		go func() {
			cmd.Wait()
		}()
		protocol.WriteFrame(stream, protocol.StreamExit, []byte("0"))
		return
	}

	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			protocol.WriteFrame(stream, protocol.StreamExit, []byte("1"))
			return
		}
		defer ptmx.Close()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStdout, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			for {
				frame, err := protocol.ReadFrame(stream)
				if err != nil {
					break
				}
				if frame.Type == protocol.StreamStdin {
					ptmx.Write(frame.Payload)
				}
			}
		}()
	} else {
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		stdin, _ := cmd.StdinPipe()

		cmd.Start()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStdout, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := stderr.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStderr, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			for {
				frame, err := protocol.ReadFrame(stream)
				if err != nil {
					break
				}
				if frame.Type == protocol.StreamStdin {
					stdin.Write(frame.Payload)
				}
			}
			stdin.Close()
		}()
	}

	cmd.Wait()
	protocol.WriteFrame(stream, protocol.StreamExit, []byte("0"))
}
