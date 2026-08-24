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
	serverURL := flag.String("url", "ws://localhost:8080/ws", "Socket URL (ws:// or wss://)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: cli [-pty] [-url <socket_url>] <target_hostname> <command>")
		os.Exit(1)
	}

	targetHostname := args[0]
	command := args[1]

	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatal(err)
	}

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	req := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
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
					Type:   protocol.TypeExecStream,
					Stream: protocol.StreamStdin,
					Data:   data,
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

		var envelope map[string]interface{}
		json.Unmarshal(message, &envelope)

		envelopeType, _ := envelope["type"].(string)
		if protocol.EnvelopeType(envelopeType) == protocol.TypeExecStream {
			var stream protocol.ExecStream
			json.Unmarshal(message, &stream)

			data, _ := base64.StdEncoding.DecodeString(stream.Data)
			switch stream.Stream {
			case protocol.StreamStdout:
				os.Stdout.Write(data)
			case protocol.StreamStderr:
				os.Stderr.Write(data)
			case protocol.StreamExit:
				os.Exit(0)
			}
		}
	}
}
