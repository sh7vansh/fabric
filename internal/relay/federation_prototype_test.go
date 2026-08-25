package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"fabric/internal/protocol"
)

// TestFederationTransitiveStreamRelayPrototype validates that Yamux streams can be
// forwarded across multiple gateway hops (Client -> Server A -> Server B -> Agent)
// with complete bidirectional data integrity and zero buffering.
func TestFederationTransitiveStreamRelayPrototype(t *testing.T) {
	// 1. Initialize Server A (Ingress Gateway) and Server B (Remote Gateway)
	serverA := New(Config{Domain: "us-east.fabric", Token: "token-a"})
	defer serverA.Close()

	serverB := New(Config{Domain: "eu-west.fabric", Token: "token-b"})
	defer serverB.Close()

	// 2. Connect Thread Agent "worker-eu" to Server B
	agentServerMux, agentClientMux := createMockMultiplexers(t)
	defer agentClientMux.Session.Close()

	meta := protocol.NodeMetadata{
		Hostname: "worker-eu",
		OS:       "linux",
		Arch:     "amd64",
		Tags:     []string{"backend"},
	}
	_, err := serverB.RegisterNode(meta, agentServerMux)
	if err != nil {
		t.Fatalf("failed to register node on Server B: %v", err)
	}

	// 3. Establish Peer Peering Link between Server A and Server B over Yamux
	peerServerBMux, peerClientAMux := createMockMultiplexers(t)
	defer peerClientAMux.Session.Close()
	defer peerServerBMux.Session.Close()

	// 4. On Server B, listen for incoming cross-gateway routed streams
	serverBStreamReceived := make(chan bool, 1)
	go func() {
		for {
			stream, err := peerServerBMux.Session.Accept()
			if err != nil {
				return
			}
			// Server B reads envelope specifying destination thread
			var raw json.RawMessage
			decoder := json.NewDecoder(stream)
			if err := decoder.Decode(&raw); err != nil {
				stream.Close()
				return
			}

			var req protocol.ExecRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				stream.Close()
				return
			}

			// Server B routes the remaining stream directly to local worker-eu
			multiReader := io.MultiReader(decoder.Buffered(), stream)
			prefixedConn := &prefixConn{Conn: stream, r: multiReader}

			err = serverB.RouteStream(req.TargetHostname, raw, prefixedConn)
			if err != nil {
				t.Errorf("Server B failed to route stream to %s: %v", req.TargetHostname, err)
			}
			serverBStreamReceived <- true
			return
		}
	}()

	// 5. On Agent worker-eu (agentClientMux), accept the routed stream and simulate an interactive echo
	agentReceivedPayload := make(chan string, 1)
	go func() {
		for {
			stream, err := agentClientMux.Session.Accept()
			if err != nil {
				return
			}
			var req protocol.ExecRequest
			decoder := json.NewDecoder(stream)
			if err := decoder.Decode(&req); err != nil {
				stream.Close()
				continue
			}

			if req.Type == protocol.TypeNodeSync {
				stream.Close()
				continue
			}

			// Read incoming data from client, including any buffered by decoder, then reply with pong
			agentReader := io.MultiReader(decoder.Buffered(), stream)
			buf := make([]byte, 128)
			n, _ := agentReader.Read(buf)
			agentReceivedPayload <- string(buf[:n])

			_, _ = stream.Write([]byte("PONG_FROM_EU_AGENT"))
			stream.Close()
			return
		}
	}()

	// 6. Client on Server A initiates command targeted at worker-eu
	clientConn, serverAStreamConn := net.Pipe()
	defer clientConn.Close()

	// Server A forwards the stream across peerClientAMux to Server B
	go func() {
		remotePeerStream, err := peerClientAMux.Session.Open()
		if err != nil {
			t.Errorf("Server A failed to open stream to Server B: %v", err)
			return
		}
		defer remotePeerStream.Close()

		execReq := protocol.ExecRequest{
			Type:           protocol.TypeExecRequest,
			TargetHostname: "worker-eu",
			Command:        "echo hello",
		}
		reqBytes, _ := json.Marshal(execReq)
		_, _ = remotePeerStream.Write(reqBytes)

		// Pipe client data to remote peer stream bidirectionally
		errCh := make(chan error, 2)
		go func() {
			_, err := io.Copy(remotePeerStream, serverAStreamConn)
			errCh <- err
		}()
		go func() {
			_, err := io.Copy(serverAStreamConn, remotePeerStream)
			errCh <- err
		}()
		<-errCh
	}()

	// 7. Client writes payload and reads response across the entire chain
	_, err = clientConn.Write([]byte("PING_FROM_CLIENT"))
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	select {
	case payload := <-agentReceivedPayload:
		if !strings.Contains(payload, "PING_FROM_CLIENT") {
			t.Errorf("expected agent to receive PING_FROM_CLIENT, got %q", payload)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for agent to receive forwarded stream")
	}

	replyBuf := make([]byte, 64)
	n, err := clientConn.Read(replyBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("client read failed: %v", err)
	}

	reply := string(replyBuf[:n])
	if !bytes.Contains([]byte(reply), []byte("PONG_FROM_EU_AGENT")) {
		t.Errorf("expected client to receive PONG_FROM_EU_AGENT, got %q", reply)
	}
}
