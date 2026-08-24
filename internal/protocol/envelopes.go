package protocol

type EnvelopeType string
type StreamType string

const (
	TypeHandshake   EnvelopeType = "handshake"
	TypeExecRequest EnvelopeType = "exec_request"
	TypeExecStream  EnvelopeType = "exec_stream"
	TypeProxyStream EnvelopeType = "proxy_stream"

	StreamStdout StreamType = "stdout"
	StreamStderr StreamType = "stderr"
	StreamStdin  StreamType = "stdin"
	StreamExit   StreamType = "exit"
)

type Handshake struct {
	Type     EnvelopeType `json:"type"`
	Hostname string       `json:"hostname"`
	Token    string       `json:"token"`
}

type ExecRequest struct {
	Type           EnvelopeType `json:"type"` // "exec_request"
	TargetHostname string       `json:"target_hostname"`
	Command        string       `json:"command"`
	AllocatePTY    bool         `json:"allocate_pty"`
}

type ExecStream struct {
	Type   EnvelopeType `json:"type"`   // "exec_stream"
	Stream StreamType   `json:"stream"` // "stdout", "stderr", "stdin", "exit"
	Data   string       `json:"data"`   // Base64 encoded chunk
}
