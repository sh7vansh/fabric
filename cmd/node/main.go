package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"sync"

	"fabric/internal/protocol"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var (
	stdinWriters     = make(map[string]io.Writer)
	stdinWritersLock sync.RWMutex
)

func main() {
	serverURL := flag.String("url", "ws://localhost:8080/ws", "Socket URL (ws:// or wss://)")
	domainFlag := flag.String("domain", "fabric.mesh", "Domain to register with the mesh")
	flag.Parse()

	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatal(err)
	}

	for {
		c := ConnectWithRetry(*u, token)

		hostname, _ := os.Hostname()
		hs := protocol.Handshake{
			Type:     protocol.TypeHandshake,
			Hostname: hostname,
			Domain:   *domainFlag,
			Token:    token,
		}

		err = c.WriteJSON(hs)
		if err != nil {
			log.Println("write handshake:", err)
			c.Close()
			continue
		}

		log.Println("Handshake sent successfully.")

		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("Read error:", err)
				break
			}

			var envelope map[string]interface{}
			if err := json.Unmarshal(message, &envelope); err != nil {
				continue
			}

			envelopeType, _ := envelope["type"].(string)
			switch protocol.EnvelopeType(envelopeType) {
			case protocol.TypeExecRequest:
				var req protocol.ExecRequest
				json.Unmarshal(message, &req)
				go handleExec(c, req)
			case protocol.TypeExecStream:
				var stream protocol.ExecStream
				json.Unmarshal(message, &stream)
				if stream.Stream == protocol.StreamStdin {
					data, _ := base64.StdEncoding.DecodeString(stream.Data)
					stdinWritersLock.RLock()
					// Since we removed SessionID, just write to the first/only stdin available for now
					for _, w := range stdinWriters {
						w.Write(data)
					}
					stdinWritersLock.RUnlock()
				}
			case protocol.TypeProxyStream:
				var stream protocol.ProxyStream
				json.Unmarshal(message, &stream)
				handleProxyStream(c, stream)
			}
		}
		c.Close()
		log.Println("Connection closed, reconnecting...")
	}
}

func streamIOToSocket(r io.Reader, c *websocket.Conn, streamType protocol.StreamType) {
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := base64.StdEncoding.EncodeToString(buf[:n])
			c.WriteJSON(protocol.ExecStream{
				Type:   protocol.TypeExecStream,
				Stream: streamType,
				Data:   data,
			})
		}
		if err != nil {
			break
		}
	}
}

func handleExec(c *websocket.Conn, req protocol.ExecRequest) {
	cmd := exec.Command("sh", "-c", req.Command)
	
	// Create a dummy session key since we removed SessionID from the struct
	sessionKey := "active_exec"

	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			sendExit(c, err.Error())
			return
		}
		defer ptmx.Close()

		stdinWritersLock.Lock()
		stdinWriters[sessionKey] = ptmx
		stdinWritersLock.Unlock()

		defer func() {
			stdinWritersLock.Lock()
			delete(stdinWriters, sessionKey)
			stdinWritersLock.Unlock()
		}()

		streamIOToSocket(ptmx, c, protocol.StreamStdout)
	} else {
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		stdin, _ := cmd.StdinPipe()

		stdinWritersLock.Lock()
		stdinWriters[sessionKey] = stdin
		stdinWritersLock.Unlock()

		defer func() {
			stdinWritersLock.Lock()
			delete(stdinWriters, sessionKey)
			stdinWritersLock.Unlock()
		}()

		cmd.Start()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			streamIOToSocket(stdout, c, protocol.StreamStdout)
		}()

		go func() {
			defer wg.Done()
			streamIOToSocket(stderr, c, protocol.StreamStderr)
		}()

		wg.Wait()
	}

	cmd.Wait()
	sendExit(c, "0")
}

func sendExit(c *websocket.Conn, code string) {
	c.WriteJSON(protocol.ExecStream{
		Type:   protocol.TypeExecStream,
		Stream: protocol.StreamExit,
		Data:   base64.StdEncoding.EncodeToString([]byte(code)),
	})
}
