package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"fabric/internal/protocol"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var (
	stdinWriters     = make(map[string]io.Writer)
	stdinWritersLock sync.RWMutex
)

func main() {
	token := os.Getenv("FABRIC_TOKEN")
	if token == "" {
		token = "default-secret"
	}

	u := url.URL{Scheme: "ws", Host: "localhost:8080", Path: "/ws"}

	for {
		c := ConnectWithRetry(u, token)

		hostname, _ := os.Hostname()
		hs := protocol.Handshake{
			Type:     "handshake",
			Hostname: hostname,
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
			Token:    token,
			LocalIP:  "127.0.0.1",
		}

		err := c.WriteJSON(hs)
		if err != nil {
			log.Println("write handshake:", err)
			c.Close()
			time.Sleep(time.Second)
			continue
		}

		log.Println("Handshake sent successfully.")

		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("Read error:", err)
				break
			}

			var env map[string]interface{}
			if err := json.Unmarshal(message, &env); err != nil {
				continue
			}

			msgType, _ := env["type"].(string)
			if msgType == "exec_request" {
				var req protocol.ExecRequest
				json.Unmarshal(message, &req)
				go handleExec(c, req)
			} else if msgType == "exec_stream" {
				var stream protocol.ExecStream
				json.Unmarshal(message, &stream)
				if stream.Stream == "stdin" {
					data, _ := base64.StdEncoding.DecodeString(stream.Data)
					stdinWritersLock.RLock()
					w, ok := stdinWriters[stream.SessionID]
					stdinWritersLock.RUnlock()
					if ok {
						w.Write(data)
					}
				}
			} else if msgType == "proxy_stream" {
				var stream protocol.ProxyStream
				json.Unmarshal(message, &stream)
				handleProxyStream(c, stream)
			}
		}
		c.Close()
		log.Println("Connection closed, reconnecting...")
	}
}

func handleExec(c *websocket.Conn, req protocol.ExecRequest) {
	cmd := exec.Command("sh", "-c", req.Command)
	
	if req.AllocatePTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			sendExit(c, req.SessionID, err.Error())
			return
		}
		defer ptmx.Close()

		stdinWritersLock.Lock()
		stdinWriters[req.SessionID] = ptmx
		stdinWritersLock.Unlock()

		defer func() {
			stdinWritersLock.Lock()
			delete(stdinWriters, req.SessionID)
			stdinWritersLock.Unlock()
		}()

		buf := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				data := base64.StdEncoding.EncodeToString(buf[:n])
				c.WriteJSON(protocol.ExecStream{
					Type:      "exec_stream",
					SessionID: req.SessionID,
					Stream:    "stdout",
					Data:      data,
				})
			}
			if err != nil {
				break
			}
		}
	} else {
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		stdin, _ := cmd.StdinPipe()

		stdinWritersLock.Lock()
		stdinWriters[req.SessionID] = stdin
		stdinWritersLock.Unlock()

		defer func() {
			stdinWritersLock.Lock()
			delete(stdinWriters, req.SessionID)
			stdinWritersLock.Unlock()
		}()

		cmd.Start()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					c.WriteJSON(protocol.ExecStream{
						Type:      "exec_stream",
						SessionID: req.SessionID,
						Stream:    "stdout",
						Data:      base64.StdEncoding.EncodeToString(buf[:n]),
					})
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
					c.WriteJSON(protocol.ExecStream{
						Type:      "exec_stream",
						SessionID: req.SessionID,
						Stream:    "stderr",
						Data:      base64.StdEncoding.EncodeToString(buf[:n]),
					})
				}
				if err != nil {
					break
				}
			}
		}()

		wg.Wait()
	}

	cmd.Wait()
	sendExit(c, req.SessionID, "0")
}

func sendExit(c *websocket.Conn, sessionID, code string) {
	c.WriteJSON(protocol.ExecStream{
		Type:      "exec_stream",
		SessionID: sessionID,
		Stream:    "exit",
		Data:      base64.StdEncoding.EncodeToString([]byte(code)),
	})
}
