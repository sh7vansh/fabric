package protocol

import (
	"encoding/binary"
	"io"
)

type StreamType byte

const (
	StreamStdout StreamType = 0
	StreamStderr StreamType = 1
	StreamStdin  StreamType = 2
	StreamExit   StreamType = 3
)

const headerSize = 8

type Frame struct {
	Type    StreamType
	Payload []byte
}

func WriteFrame(w io.Writer, streamType StreamType, payload []byte) error {
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

	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Frame{
		Type:    streamType,
		Payload: payload,
	}, nil
}
