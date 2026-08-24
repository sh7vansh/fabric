package protocol

import (
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/hashicorp/yamux"
)

func TestRouter_InMem(t *testing.T) {
	// We use net.Pipe() to simulate the underlying connection for Yamux.
	// We skip the WebSocketConn wrapper here because that would require an actual HTTP/WS server,
	// and here we mainly want to test the routing and buffering logic of the Router.
	clientConn, serverConn := net.Pipe()

	serverSession, err := yamux.Server(serverConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux.Server err: %v", err)
	}

	clientSession, err := yamux.Client(clientConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux.Client err: %v", err)
	}

	router := NewRouter(serverSession)
	
	var wg sync.WaitGroup
	wg.Add(1)

	// Register the handler
	router.HandleFunc("ExecRequest", func(conn net.Conn, envelope []byte) {
		defer wg.Done()
		var env Envelope
		if err := json.Unmarshal(envelope, &env); err != nil {
			t.Errorf("unmarshal error: %v", err)
		}
		if env.Type != "ExecRequest" {
			t.Errorf("expected ExecRequest, got %v", env.Type)
		}

		// Read the rest of the stream
		data, err := io.ReadAll(conn)
		if err != nil {
			t.Errorf("read error: %v", err)
		}
		if string(data) != "hello world" {
			t.Errorf("expected 'hello world', got %q", string(data))
		}
	})

	go router.Accept()

	// Client opens a stream and sends data
	stream, err := clientSession.Open()
	if err != nil {
		t.Fatalf("client.Open err: %v", err)
	}

	// Payload with Envelope first, then raw binary
	type execReq struct {
		Type string `json:"type"`
		Cmd  string `json:"cmd"`
	}

	req := execReq{Type: "ExecRequest", Cmd: "echo"}
	b, _ := json.Marshal(req)

	// We append some padding or directly the binary payload to ensure the json.Decoder buffers it
	// and our io.MultiReader replays it correctly.
	payload := append(b, []byte("hello world")...)

	_, err = stream.Write(payload)
	if err != nil {
		t.Fatalf("stream.Write err: %v", err)
	}

	// Close stream so io.ReadAll finishes
	stream.Close()

	// Wait for handler to complete
	wg.Wait()
}
