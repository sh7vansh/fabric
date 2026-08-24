package protocol

// ProxyStream multiplexes raw TCP/HTTP proxy traffic over the single WebSocket.
// This resolves the fog around multiplexing execution payloads and raw proxy data
// by wrapping the raw proxy bytes in the same JSON envelope structure.
type ProxyStream struct {
	Type     EnvelopeType `json:"type"`      // "proxy_stream"
	ConnID   string       `json:"conn_id"`   // Unique ID for the proxy connection
	Data     string       `json:"data"`      // Base64 encoded TCP chunk
	IsClosed bool         `json:"is_closed"` // Signals connection termination
}
