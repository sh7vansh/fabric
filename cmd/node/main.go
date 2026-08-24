package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"fabric/internal/meshdns"
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
	flag.Parse()

	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatal(err)
	}

	meshdns.RevertOS()
	meshdns.CleanHostsBlock()

	resolver := meshdns.NewResolver(*domainFlag)
	if err := resolver.Start(); err != nil {
		log.Fatalf("Failed to start DNS resolver: %v", err)
	}

	if err := meshdns.ConfigureOS(*domainFlag); err != nil {
		log.Printf("Failed to configure OS DNS routing: %v", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("Shutting down... Reverting OS DNS configuration.")
		meshdns.RevertOS()
		meshdns.CleanHostsBlock()
		resolver.Stop()
		os.Exit(0)
	}()

	for {
		c := ConnectWithRetry(*u, token)

		mux, err := protocol.NewStreamMultiplexer(c, false)
		resolver.SetMultiplexer(mux)
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

		hostname, _ := os.Hostname()
		hs := protocol.Handshake{
			Type:     protocol.TypeHandshake,
			Hostname: hostname,
			Domain:   *domainFlag,
			Token:    token,
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
			Version:  "1.0.0",
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
			meshdns.UpdateHostsBlock(syncMsg.Nodes, *domainFlag, *serverURL)
		})

		router.HandleFunc(string(protocol.TypeDNSResponse), func(s net.Conn, env []byte) {
			defer s.Close()
			var resp protocol.DNSResponse
			json.Unmarshal(env, &resp)
			resolver.HandleDNSResponse(resp)
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

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
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
			defer wg.Done()
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

		wg.Wait()
	}

	cmd.Wait()
	protocol.WriteFrame(stream, protocol.StreamExit, []byte("0"))
}
