package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"fabric/internal/protocol"

	"github.com/gorilla/websocket"
)

func main() {
	ptyFlag := flag.Bool("pty", false, "Allocate a pseudo-terminal")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: cli [-pty] <target_hostname> <command>")
		os.Exit(1)
	}

	targetHostname := args[0]
	command := args[1]

	u := url.URL{Scheme: "ws", Host: "localhost:8080", Path: "/ws"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	sessionID := "session-1" // hardcoded for simple prototype

	req := protocol.ExecRequest{
		Type:           "exec_request",
		SessionID:      sessionID,
		TargetHostname: targetHostname,
		Command:        command,
		AllocatePTY:    *ptyFlag,
	}

	err = c.WriteJSON(req)
	if err != nil {
		log.Fatal("write:", err)
	}

	// Read from stdin and send as exec_stream
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				data := base64.StdEncoding.EncodeToString(buf[:n])
				c.WriteJSON(protocol.ExecStream{
					Type:      "exec_stream",
					SessionID: sessionID,
					Stream:    "stdin",
					Data:      data,
				})
			}
			if err != nil {
				break
			}
		}
	}()

	// Read from websocket and write to stdout/stderr
	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Fatal("read:", err)
			return
		}

		var env map[string]interface{}
		json.Unmarshal(message, &env)

		msgType, _ := env["type"].(string)
		if msgType == "exec_stream" {
			var stream protocol.ExecStream
			json.Unmarshal(message, &stream)

			data, _ := base64.StdEncoding.DecodeString(stream.Data)
			if stream.Stream == "stdout" {
				os.Stdout.Write(data)
			} else if stream.Stream == "stderr" {
				os.Stderr.Write(data)
			} else if stream.Stream == "exit" {
				os.Exit(0)
			}
		}
	}
}
