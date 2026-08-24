package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"
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
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
			Version:  "1.0.0",
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
					if w, ok := stdinWriters[stream.SessionID]; ok {
						w.Write(data)
					}
					stdinWritersLock.RUnlock()
				}
			case protocol.TypeCopyRequest:
				var req protocol.CopyRequest
				json.Unmarshal(message, &req)
				handleCopyRequest(c, req)
			case protocol.TypeCopyStream:
				var stream protocol.CopyStream
				json.Unmarshal(message, &stream)
				handleCopyStream(stream)
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

func streamIOToSocket(r io.Reader, c *websocket.Conn, sessionID string, streamType protocol.StreamType) {
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := base64.StdEncoding.EncodeToString(buf[:n])
			c.WriteJSON(protocol.ExecStream{
				Type:      protocol.TypeExecStream,
				SessionID: sessionID,
				Stream:    streamType,
				Data:      data,
			})
		}
		if err != nil {
			break
		}
	}
}

func handleExec(c *websocket.Conn, req protocol.ExecRequest) {
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
			sendExit(c, req.SessionID, "1")
			return
		}
		go func() {
			cmd.Wait()
		}()
		sendExit(c, req.SessionID, "0")
		return
	}

	sessionKey := req.SessionID

	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			sendExit(c, req.SessionID, "1")
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

		streamIOToSocket(ptmx, c, req.SessionID, protocol.StreamStdout)
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
			streamIOToSocket(stdout, c, req.SessionID, protocol.StreamStdout)
		}()

		go func() {
			defer wg.Done()
			streamIOToSocket(stderr, c, req.SessionID, protocol.StreamStderr)
		}()

		wg.Wait()
	}

	cmd.Wait()
	sendExit(c, req.SessionID, "0")
}

func sendExit(c *websocket.Conn, sessionID string, code string) {
	c.WriteJSON(protocol.ExecStream{
		Type:      protocol.TypeExecStream,
		SessionID: sessionID,
		Stream:    protocol.StreamExit,
		Data:      base64.StdEncoding.EncodeToString([]byte(code)),
	})
}
