package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFramingReadWrite(t *testing.T) {
	var buf bytes.Buffer

	payload := []byte("hello stream framing")
	if err := WriteFrame(&buf, StreamStdout, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != StreamStdout {
		t.Errorf("expected StreamStdout (%d), got %d", StreamStdout, frame.Type)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("expected payload %q, got %q", payload, frame.Payload)
	}
}

func TestFramingOversizeHeaderRejection(t *testing.T) {
	// Construct a malicious header specifying 2 GB payload
	var buf bytes.Buffer
	header := make([]byte, headerSize)
	header[0] = byte(StreamStdout)
	binary.BigEndian.PutUint32(header[4:], uint32(2*1024*1024*1024))
	buf.Write(header)

	frame, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected ReadFrame to return error for oversize frame, got nil (frame: %+v)", frame)
	}
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected errors.Is(err, ErrFrameTooLarge), got %v", err)
	}
	if frame != nil {
		t.Errorf("expected nil frame on oversize error, got: %+v", frame)
	}
}

func TestFramingWriteOversizeRejection(t *testing.T) {
	var buf bytes.Buffer
	oversizePayload := make([]byte, MaxFramePayloadSize+1)
	err := WriteFrame(&buf, StreamStdout, oversizePayload)
	if err == nil {
		t.Fatalf("expected WriteFrame to return error for payload > MaxFramePayloadSize, got nil")
	}
}

func TestFramingIncrementalReadTruncatedStream(t *testing.T) {
	// Construct a frame header claiming 10 MB payload, but stream only provides 16 bytes
	var buf bytes.Buffer
	header := make([]byte, headerSize)
	header[0] = byte(StreamStderr)
	binary.BigEndian.PutUint32(header[4:], 10*1024*1024)
	buf.Write(header)
	buf.Write([]byte("short 16-b chunk"))

	frame, err := ReadFrame(&buf)
	if err == nil {
		t.Fatalf("expected ReadFrame to return error for truncated stream, got frame: %+v", frame)
	}
	if frame != nil {
		t.Errorf("expected nil frame on truncated stream error, got: %+v", frame)
	}
}

func TestFramingEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, StreamExit, []byte("")); err != nil {
		t.Fatalf("WriteFrame with empty payload failed: %v", err)
	}

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame with empty payload failed: %v", err)
	}
	if frame.Type != StreamExit {
		t.Errorf("expected StreamExit (%d), got %d", StreamExit, frame.Type)
	}
	if len(frame.Payload) != 0 {
		t.Errorf("expected empty payload, got %q", frame.Payload)
	}
}

