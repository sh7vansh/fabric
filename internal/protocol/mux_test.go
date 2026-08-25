package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

func setupWSPair(t *testing.T) (*WebSocketConn, *WebSocketConn, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	serverConnChan := make(chan *websocket.Conn, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade err: %v", err)
			return
		}
		serverConnChan <- c
	}))

	u := "ws" + strings.TrimPrefix(s.URL, "http")
	clientWS, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		s.Close()
		t.Fatalf("Dial err: %v", err)
	}

	serverWS := <-serverConnChan
	serverConn := NewWebSocketConn(serverWS)
	clientConn := NewWebSocketConn(clientWS)

	cleanup := func() {
		clientConn.Close()
		serverConn.Close()
		s.Close()
	}

	return clientConn, serverConn, cleanup
}

func TestWebSocketConn_ConcurrentWrites(t *testing.T) {
	clientConn, serverConn, cleanup := setupWSPair(t)
	defer cleanup()

	const numGoroutines = 64
	const writesPerGoroutine = 50
	const totalWrites = numGoroutines * writesPerGoroutine
	const payloadSize = 128

	var receiveErr error
	var receiveWg sync.WaitGroup
	receiveWg.Add(1)

	// Receiver goroutine: reads totalWrites complete messages from serverConn.
	go func() {
		defer receiveWg.Done()
		for i := 0; i < totalWrites; i++ {
			msgType, data, err := serverConn.conn.ReadMessage()
			if err != nil {
				receiveErr = fmt.Errorf("read error at msg %d: %w", i, err)
				return
			}
			if msgType != websocket.BinaryMessage {
				receiveErr = fmt.Errorf("expected BinaryMessage, got %d", msgType)
				return
			}
			if len(data) != payloadSize {
				receiveErr = fmt.Errorf("expected payload length %d, got %d", payloadSize, len(data))
				return
			}
			// Verify payload integrity: first 4 bytes is gID, next 4 bytes is seq, rest is byte matching gID
			gID := binary.BigEndian.Uint32(data[0:4])
			seq := binary.BigEndian.Uint32(data[4:8])
			if gID >= numGoroutines || seq >= writesPerGoroutine {
				receiveErr = fmt.Errorf("corrupt payload header: gID=%d, seq=%d", gID, seq)
				return
			}
			expectedByte := byte(gID ^ seq)
			for j := 8; j < payloadSize; j++ {
				if data[j] != expectedByte {
					receiveErr = fmt.Errorf("corrupt payload data at byte %d in gID=%d seq=%d: expected %v, got %v", j, gID, seq, expectedByte, data[j])
					return
				}
			}
		}
	}()

	var writeWg sync.WaitGroup
	startBarrier := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		writeWg.Add(1)
		go func(gID uint32) {
			defer writeWg.Done()
			<-startBarrier

			for s := 0; s < writesPerGoroutine; s++ {
				payload := make([]byte, payloadSize)
				binary.BigEndian.PutUint32(payload[0:4], gID)
				binary.BigEndian.PutUint32(payload[4:8], uint32(s))
				fillByte := byte(gID ^ uint32(s))
				for j := 8; j < payloadSize; j++ {
					payload[j] = fillByte
				}

				n, err := clientConn.Write(payload)
				if err != nil {
					t.Errorf("goroutine %d write %d failed: %v", gID, s, err)
					return
				}
				if n != len(payload) {
					t.Errorf("goroutine %d write %d short write: expected %d, got %d", gID, s, len(payload), n)
					return
				}
			}
		}(uint32(g))
	}

	// Release all writers at the same time
	close(startBarrier)
	writeWg.Wait()
	receiveWg.Wait()

	if receiveErr != nil {
		t.Fatalf("receiver error: %v", receiveErr)
	}

	// Verify the connection remains usable afterward
	pingMsg := []byte("ping-usable-check")
	if _, err := clientConn.Write(pingMsg); err != nil {
		t.Fatalf("post-concurrency client write failed: %v", err)
	}

	readBuf := make([]byte, len(pingMsg))
	if _, err := io.ReadFull(serverConn, readBuf); err != nil {
		t.Fatalf("post-concurrency server read failed: %v", err)
	}
	if !bytes.Equal(readBuf, pingMsg) {
		t.Fatalf("post-concurrency read mismatch: expected %q, got %q", pingMsg, readBuf)
	}

	pongMsg := []byte("pong-usable-check")
	if _, err := serverConn.Write(pongMsg); err != nil {
		t.Fatalf("post-concurrency server write failed: %v", err)
	}

	clientReadBuf := make([]byte, len(pongMsg))
	if _, err := io.ReadFull(clientConn, clientReadBuf); err != nil {
		t.Fatalf("post-concurrency client read failed: %v", err)
	}
	if !bytes.Equal(clientReadBuf, pongMsg) {
		t.Fatalf("post-concurrency read mismatch: expected %q, got %q", pongMsg, clientReadBuf)
	}
}

func TestStreamMultiplexer_ConcurrentStreams(t *testing.T) {
	clientConn, serverConn, cleanup := setupWSPair(t)
	defer cleanup()

	serverMux, err := NewStreamMultiplexer(serverConn.conn, true)
	if err != nil {
		t.Fatalf("NewStreamMultiplexer(server) err: %v", err)
	}
	defer serverMux.Session.Close()

	clientMux, err := NewStreamMultiplexer(clientConn.conn, false)
	if err != nil {
		t.Fatalf("NewStreamMultiplexer(client) err: %v", err)
	}
	defer clientMux.Session.Close()

	const numStreams = 64
	const streamDataSize = 4096

	var serverWg sync.WaitGroup
	serverWg.Add(numStreams)

	// Server accepts numStreams streams and echoes data back
	go func() {
		for i := 0; i < numStreams; i++ {
			stream, err := serverMux.Session.Accept()
			if err != nil {
				t.Errorf("server Accept err: %v", err)
				return
			}
			go func(s net.Conn) {
				defer serverWg.Done()
				defer s.Close()

				buf := make([]byte, streamDataSize)
				if _, err := io.ReadFull(s, buf); err != nil {
					t.Errorf("server ReadFull err: %v", err)
					return
				}
				if _, err := s.Write(buf); err != nil {
					t.Errorf("server Write err: %v", err)
					return
				}
			}(stream)
		}
	}()

	var clientWg sync.WaitGroup
	startBarrier := make(chan struct{})

	for i := 0; i < numStreams; i++ {
		clientWg.Add(1)
		go func(streamIdx int) {
			defer clientWg.Done()
			<-startBarrier

			stream, err := clientMux.Session.Open()
			if err != nil {
				t.Errorf("client Open stream %d err: %v", streamIdx, err)
				return
			}
			defer stream.Close()

			payload := bytes.Repeat([]byte{byte(streamIdx + 1)}, streamDataSize)
			if _, err := stream.Write(payload); err != nil {
				t.Errorf("client stream %d Write err: %v", streamIdx, err)
				return
			}

			resp := make([]byte, streamDataSize)
			if _, err := io.ReadFull(stream, resp); err != nil {
				t.Errorf("client stream %d ReadFull err: %v", streamIdx, err)
				return
			}

			if !bytes.Equal(payload, resp) {
				t.Errorf("client stream %d data mismatch", streamIdx)
			}
		}(i)
	}

	// Trigger all client streams concurrently
	close(startBarrier)

	clientWg.Wait()
	serverWg.Wait()

	if clientMux.Session.IsClosed() {
		t.Fatalf("client Yamux session unexpectedly closed")
	}
	if serverMux.Session.IsClosed() {
		t.Fatalf("server Yamux session unexpectedly closed")
	}
}

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
