package protocol_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"fabric/internal/protocol"
)

func TestStreamManager_Bridge_BasicTransfer(t *testing.T) {
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		BufferSize: 32 * 1024,
	})

	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	defer a1.Close()
	defer b2.Close()

	go func() {
		_, _ = sm.Bridge(a2, b1)
	}()

	msgA := []byte("Hello from client A")
	msgB := []byte("Hello from server B")

	// Write A -> B
	go func() {
		_, _ = a1.Write(msgA)
	}()

	bufB := make([]byte, len(msgA))
	if _, err := io.ReadFull(b2, bufB); err != nil {
		t.Fatalf("failed to read on b2: %v", err)
	}
	if !bytes.Equal(bufB, msgA) {
		t.Fatalf("expected %q, got %q", msgA, bufB)
	}

	// Write B -> A
	go func() {
		_, _ = b2.Write(msgB)
	}()

	bufA := make([]byte, len(msgB))
	if _, err := io.ReadFull(a1, bufA); err != nil {
		t.Fatalf("failed to read on a1: %v", err)
	}
	if !bytes.Equal(bufA, msgB) {
		t.Fatalf("expected %q, got %q", msgB, bufA)
	}

	_ = a1.Close()
	_ = b2.Close()
}

func TestStreamManager_LargeTransfer_Telemetry(t *testing.T) {
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		BufferSize: 32 * 1024,
	})

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()

	var bridgeTelem *protocol.StreamTelemetry
	var bridgeErr error
	done := make(chan struct{})

	// Setup bridge between incoming A and incoming B
	go func() {
		defer close(done)
		connA, errA := lnA.Accept()
		if errA != nil {
			return
		}
		connB, errB := lnB.Accept()
		if errB != nil {
			connA.Close()
			return
		}
		bridgeTelem, bridgeErr = sm.Bridge(connA, connB)
	}()

	clientA, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	clientB, err := net.Dial("tcp", lnB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	// Send 512KB from A to B
	payloadSize := 512 * 1024
	payloadA := make([]byte, payloadSize)
	_, _ = rand.Read(payloadA)

	recvDone := make(chan struct{})
	var receivedB []byte
	go func() {
		defer close(recvDone)
		buf := make([]byte, payloadSize)
		_, _ = io.ReadFull(clientB, buf)
		receivedB = buf
	}()

	_, _ = clientA.Write(payloadA)
	<-recvDone

	if !bytes.Equal(receivedB, payloadA) {
		t.Fatalf("transferred payload mismatch")
	}

	_ = clientA.Close()
	_ = clientB.Close()
	<-done

	if bridgeErr != nil {
		t.Fatalf("unexpected bridge error: %v", bridgeErr)
	}
	if bridgeTelem == nil {
		t.Fatalf("expected telemetry from bridge")
	}
	if bridgeTelem.BytesFromAToB != int64(payloadSize) {
		t.Errorf("expected %d bytes A->B, got %d", payloadSize, bridgeTelem.BytesFromAToB)
	}
	if bridgeTelem.Duration <= 0 {
		t.Errorf("expected positive duration in telemetry")
	}
}

func TestStreamManager_CircuitBreaker_MaxStreams(t *testing.T) {
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		MaxActiveStreams: 2,
	})

	c1a, c1b := net.Pipe()
	c2a, c2b := net.Pipe()
	c3a, c3b := net.Pipe()

	defer c1a.Close()
	defer c1b.Close()
	defer c2a.Close()
	defer c2b.Close()
	defer c3a.Close()
	defer c3b.Close()

	go func() { _, _ = sm.Bridge(c1a, c1b) }()
	go func() { _, _ = sm.Bridge(c2a, c2b) }()

	time.Sleep(50 * time.Millisecond)

	stats := sm.Stats()
	if stats.ActiveStreams != 2 {
		t.Fatalf("expected 2 active streams, got %d", stats.ActiveStreams)
	}

	// 3rd stream must be rejected by circuit breaker
	_, err := sm.Bridge(c3a, c3b)
	if err != protocol.ErrMaxStreamsExceeded {
		t.Fatalf("expected ErrMaxStreamsExceeded, got: %v", err)
	}
}

func TestStreamManager_IdleDeadline(t *testing.T) {
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		IdleDeadline: 100 * time.Millisecond,
	})

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		connA, _ := lnA.Accept()
		connB, _ := lnB.Accept()
		if connA != nil && connB != nil {
			_, _ = sm.Bridge(connA, connB)
		}
	}()

	clientA, _ := net.Dial("tcp", lnA.Addr().String())
	clientB, _ := net.Dial("tcp", lnB.Addr().String())
	defer clientA.Close()
	defer clientB.Close()

	// Do not send data, wait for idle deadline to close bridge
	select {
	case <-done:
		// Sockets timed out and bridge closed cleanly
	case <-time.After(1 * time.Second):
		t.Fatalf("bridge did not timeout on idle deadline")
	}
}

func TestStreamManager_HalfClose_Propagation(t *testing.T) {
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		BufferSize: 32 * 1024,
	})

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		connA, errA := lnA.Accept()
		if errA != nil {
			return
		}
		connB, errB := lnB.Accept()
		if errB != nil {
			connA.Close()
			return
		}
		_, _ = sm.Bridge(connA, connB)
	}()

	clientA, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()

	serverB, err := net.Dial("tcp", lnB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()

	reqMsg := []byte("client request payload")
	respMsg := []byte("server response after half-close")

	// 1. Client A sends request
	_, _ = clientA.Write(reqMsg)

	// 2. Client A shuts down write side (half-close)
	tcpClientA := clientA.(*net.TCPConn)
	if err := tcpClientA.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}

	// 3. Server B reads until EOF
	receivedReq := make([]byte, len(reqMsg))
	if _, err := io.ReadFull(serverB, receivedReq); err != nil {
		t.Fatalf("Server B failed to read request: %v", err)
	}
	if !bytes.Equal(receivedReq, reqMsg) {
		t.Fatalf("expected req %q, got %q", reqMsg, receivedReq)
	}

	// 4. Server B sends response to Client A AFTER client A half-closed
	time.Sleep(20 * time.Millisecond)
	_, err = serverB.Write(respMsg)
	if err != nil {
		t.Fatalf("Server B failed to write response: %v", err)
	}
	_ = serverB.Close()

	// 5. Client A reads response
	receivedResp, err := io.ReadAll(clientA)
	if err != nil {
		t.Fatalf("Client A failed to read response: %v", err)
	}
	if !bytes.Equal(receivedResp, respMsg) {
		t.Fatalf("expected resp %q, got %q", respMsg, receivedResp)
	}

	<-done
}

func TestStreamManager_NonHalfClose_CleanEOF_ImmediateTeardown(t *testing.T) {
	// Set an idle deadline of 10 seconds to ensure that any hang would trigger test failure
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		BufferSize:   32 * 1024,
		IdleDeadline: 10 * time.Second,
	})

	// net.Pipe returns synchronous memory pipes that DO NOT implement CloseWrite
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	done := make(chan struct{})
	var bridgeTelem *protocol.StreamTelemetry
	var bridgeErr error

	go func() {
		defer close(done)
		bridgeTelem, bridgeErr = sm.Bridge(a2, b1)
	}()

	msg := []byte("payload to be sent and closed")

	// a1 writes message and then closes (sending io.EOF to a2)
	go func() {
		_, _ = a1.Write(msg)
		_ = a1.Close()
	}()

	// b2 reads until EOF
	received, err := io.ReadAll(b2)
	if err != nil {
		t.Fatalf("failed reading on b2: %v", err)
	}
	if !bytes.Equal(received, msg) {
		t.Fatalf("expected %q, got %q", msg, received)
	}

	// The bridge must terminate immediately (within milliseconds), rather than waiting for 10s idle deadline
	select {
	case <-done:
		// Bridge finished promptly
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("bridge stalled on EOF over non-half-close transport without immediate teardown")
	}

	if bridgeErr != nil {
		t.Fatalf("unexpected bridge error: %v", bridgeErr)
	}
	if bridgeTelem == nil {
		t.Fatalf("expected telemetry from bridge")
	}
	if bridgeTelem.BytesFromAToB != int64(len(msg)) {
		t.Errorf("expected %d bytes, got %d", len(msg), bridgeTelem.BytesFromAToB)
	}
}

type errConnWithCloseWrite struct {
	net.Conn
	closeWriteCalled bool
	closed           bool
	mu               sync.Mutex
}

func (c *errConnWithCloseWrite) Write(b []byte) (n int, err error) {
	return 0, errors.New("simulated fatal write error")
}

func (c *errConnWithCloseWrite) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeWriteCalled = true
	return nil
}

func (c *errConnWithCloseWrite) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.Conn.Close()
}

func TestStreamManager_HardWriteError_ImmediateTeardownEvenWithCloseWrite(t *testing.T) {
	sm := protocol.NewStreamManager(protocol.StreamManagerConfig{
		BufferSize:   32 * 1024,
		IdleDeadline: 10 * time.Second,
	})

	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer b2.Close()
	errB1 := &errConnWithCloseWrite{Conn: b1}

	done := make(chan struct{})
	var bridgeTelem *protocol.StreamTelemetry
	var bridgeErr error

	go func() {
		defer close(done)
		bridgeTelem, bridgeErr = sm.Bridge(a2, errB1)
	}()

	// Write from a1 to trigger write on errB1 which fails with fatal write error
	go func() {
		_, _ = a1.Write([]byte("trigger write"))
	}()

	select {
	case <-done:
		// Bridge should immediately close both sides upon write error
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("bridge stalled and did not tear down both sides on fatal write error")
	}

	if bridgeErr != nil {
		t.Fatalf("unexpected fatal bridge framework error: %v", bridgeErr)
	}
	if bridgeTelem == nil || bridgeTelem.ErrB == nil {
		t.Fatalf("expected non-nil ErrB in telemetry on fatal write, got %v", bridgeTelem)
	}

	// Verify a2 is closed (writing or reading on a1 returns error)
	buf := make([]byte, 10)
	_ = a1.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := a1.Read(buf)
	if err == nil {
		t.Errorf("expected error reading from closed connection a1")
	}
}

