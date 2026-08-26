package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

type StreamType byte

const (
	StreamStdout StreamType = 0
	StreamStderr StreamType = 1
	StreamStdin  StreamType = 2
	StreamExit   StreamType = 3
)

// MaxFramePayloadSize is the upper ceiling (16 MB) for a single stream frame payload.
const MaxFramePayloadSize = 16 * 1024 * 1024

// ErrFrameTooLarge is returned when an incoming frame header claims a payload size exceeding MaxFramePayloadSize.
var ErrFrameTooLarge = errors.New("frame payload exceeds maximum allowed size")

const headerSize = 8

type Frame struct {
	Type    StreamType
	Payload []byte
}

func WriteFrame(w io.Writer, streamType StreamType, payload []byte) error {
	if len(payload) > MaxFramePayloadSize {
		return io.ErrShortWrite
	}

	header := make([]byte, headerSize)
	header[0] = byte(streamType)
	// bytes 1, 2, 3 are 0
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	streamType := StreamType(header[0])
	size := binary.BigEndian.Uint32(header[4:])

	if size > MaxFramePayloadSize {
		return nil, ErrFrameTooLarge
	}

	if size == 0 {
		return &Frame{
			Type:    streamType,
			Payload: nil,
		}, nil
	}

	// Bounded reading: allocate incrementally rather than allocating upfront 'size' bytes
	// which prevents memory exhaustion DoS when a client sends a large size in the header
	// but sends few or no actual bytes.
	initCap := size
	if initCap > 4096 {
		initCap = 4096
	}
	payload := make([]byte, 0, initCap)
	tmp := make([]byte, 32*1024)
	var totalRead uint32

	for totalRead < size {
		toRead := int(size - totalRead)
		if toRead > len(tmp) {
			toRead = len(tmp)
		}
		n, err := r.Read(tmp[:toRead])
		if n > 0 {
			payload = append(payload, tmp[:n]...)
			totalRead += uint32(n)
		}
		if err != nil {
			if err == io.EOF && totalRead < size {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}

	return &Frame{
		Type:    streamType,
		Payload: payload,
	}, nil
}
