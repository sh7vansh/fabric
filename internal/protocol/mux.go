package protocol

import (
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// WebSocketConn wraps a *websocket.Conn to implement net.Conn.
type WebSocketConn struct {
	conn *websocket.Conn
	r    io.Reader
}

// NewWebSocketConn creates a net.Conn wrapping a websocket connection.
func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{conn: conn}
}

// Read reads from the websocket connection.
func (w *WebSocketConn) Read(p []byte) (int, error) {
	if w.r == nil {
		_, r, err := w.conn.NextReader()
		if err != nil {
			return 0, err
		}
		w.r = r
	}
	n, err := w.r.Read(p)
	if err != nil {
		if err == io.EOF {
			w.r = nil
			if n > 0 {
				return n, nil
			}
			// Recurse to read from the next message
			return w.Read(p)
		}
		return n, err
	}
	return n, nil
}

// Write writes a binary message to the websocket.
func (w *WebSocketConn) Write(p []byte) (int, error) {
	err := w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying websocket connection.
func (w *WebSocketConn) Close() error {
	return w.conn.Close()
}

// LocalAddr returns the local network address.
func (w *WebSocketConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (w *WebSocketConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (w *WebSocketConn) SetDeadline(t time.Time) error {
	if err := w.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return w.conn.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (w *WebSocketConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (w *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// StreamMultiplexer wraps a *websocket.Conn and initializes a yamux.Session.
type StreamMultiplexer struct {
	Session *yamux.Session
}

// NewStreamMultiplexer creates a new StreamMultiplexer over a websocket connection.
func NewStreamMultiplexer(conn *websocket.Conn, isServer bool) (*StreamMultiplexer, error) {
	wsConn := NewWebSocketConn(conn)
	var session *yamux.Session
	var err error

	config := yamux.DefaultConfig()
	// Optionally tweak config.KeepAliveInterval if needed

	if isServer {
		session, err = yamux.Server(wsConn, config)
	} else {
		session, err = yamux.Client(wsConn, config)
	}

	if err != nil {
		return nil, err
	}

	return &StreamMultiplexer{Session: session}, nil
}

// Router takes a *yamux.Session and routes incoming streams based on a JSON envelope.
type Router struct {
	session  *yamux.Session
	handlers map[string]func(conn net.Conn, envelope []byte)
}

// NewRouter creates a new stream router.
func NewRouter(session *yamux.Session) *Router {
	return &Router{
		session:  session,
		handlers: make(map[string]func(conn net.Conn, envelope []byte)),
	}
}

// HandleFunc registers a handler for a specific message type.
func (r *Router) HandleFunc(msgType string, handler func(conn net.Conn, envelope []byte)) {
	r.handlers[msgType] = handler
}

// Envelope represents the initial JSON message sent over a new stream to determine routing.
type Envelope struct {
	Type string `json:"type"`
}

// prefixConn wraps a net.Conn with a prefix reader, useful to replay buffered bytes
// that might have been consumed by a JSON decoder.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// Accept loops over yamuxSession.Accept(), reads the envelope, and routes the stream.
func (r *Router) Accept() error {
	for {
		stream, err := r.session.Accept()
		if err != nil {
			return err
		}

		go r.handleStream(stream)
	}
}

func (r *Router) handleStream(stream net.Conn) {
	var raw json.RawMessage
	decoder := json.NewDecoder(stream)

	// Decode reads the next JSON-encoded value from the stream and stores it in raw.
	if err := decoder.Decode(&raw); err != nil {
		stream.Close()
		return
	}

	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		stream.Close()
		return
	}

	if handler, ok := r.handlers[env.Type]; ok {
		// Reconstruct conn to include any buffered bytes that were over-read by the JSON decoder
		multiReader := io.MultiReader(decoder.Buffered(), stream)
		wrappedStream := &prefixConn{
			Conn: stream,
			r:    multiReader,
		}
		handler(wrappedStream, []byte(raw))
	} else {
		// Unknown route, close stream
		stream.Close()
	}
}
