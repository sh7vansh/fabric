package protocol_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
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
