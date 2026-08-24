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
	Domain   string       `json:"domain,omitempty"`
	Token    string       `json:"token"`
	OS       string       `json:"os,omitempty"`
	Arch     string       `json:"arch,omitempty"`
	Version  string       `json:"version,omitempty"`
}

type ExecRequest struct {
	Type           EnvelopeType `json:"type"` // "exec_request"
	SessionID      string       `json:"session_id"`
	TargetHostname string       `json:"target_hostname"`
	Command        string       `json:"command"`
	AllocatePTY    bool         `json:"allocate_pty"`
	Interactive    bool         `json:"interactive"`
	Detached       bool         `json:"detached"`
	Env            []string     `json:"env,omitempty"`
	WorkDir        string       `json:"workdir,omitempty"`
	User           string       `json:"user,omitempty"`
}

type ExecStream struct {
	Type      EnvelopeType `json:"type"`       // "exec_stream"
	SessionID string       `json:"session_id"` // Matches ExecRequest
	Stream    StreamType   `json:"stream"`     // "stdout", "stderr", "stdin", "exit"
	Data      string       `json:"data"`       // Base64 encoded chunk
}

type NodeMetadata struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	RemoteIP    string `json:"remote_ip"`
	Status      string `json:"status"` // "online"
	ConnectedAt string `json:"connected_at"`
	LastSeen    string `json:"last_seen"`
	Uptime      string `json:"uptime"`
}

const (
	TypeCopyRequest EnvelopeType = "copy_request"
	TypeCopyStream  EnvelopeType = "copy_stream"
)

type CopyRequest struct {
	Type           EnvelopeType `json:"type"` // "copy_request"
	TransferID     string       `json:"transfer_id"`
	TargetHostname string       `json:"target_hostname"`
	Direction      string       `json:"direction"` // "upload" or "download"
	RemotePath     string       `json:"remote_path"`
}

type CopyStream struct {
	Type       EnvelopeType `json:"type"` // "copy_stream"
	TransferID string       `json:"transfer_id"`
	Data       string       `json:"data"` // Base64 encoded tar chunk
	IsEOF      bool         `json:"is_eof"`
}
