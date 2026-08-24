package protocol

type Handshake struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Token    string `json:"token"`
	LocalIP  string `json:"local_ip"`
}

type ExecRequest struct {
	Type           string `json:"type"` // "exec_request"
	SessionID      string `json:"session_id"`
	TargetHostname string `json:"target_hostname"`
	Command        string `json:"command"`
	AllocatePTY    bool   `json:"allocate_pty"`
}

type ExecStream struct {
	Type      string `json:"type"`       // "exec_stream"
	SessionID string `json:"session_id"`
	Stream    string `json:"stream"`     // "stdout", "stderr", "stdin", "exit"
	Data      string `json:"data"`       // Base64 encoded chunk
}
