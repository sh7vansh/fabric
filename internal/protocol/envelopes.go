package protocol

type EnvelopeType string

const (
	TypeHandshake   EnvelopeType = "handshake"
	TypeExecRequest EnvelopeType = "exec_request"
)

type Handshake struct {
	Type      EnvelopeType `json:"type"`
	SessionID string       `json:"session_id,omitempty"`
	Hostname  string       `json:"hostname"`
	Domain    string       `json:"domain,omitempty"`
	Token     string   `json:"token"`
	OS        string   `json:"os,omitempty"`
	Arch      string   `json:"arch,omitempty"`
	Version   string   `json:"version,omitempty"`
	Tags      []string `json:"tags,omitempty"`
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

type NodeMetadata struct {
	ID          string   `json:"id"`
	SessionID   string   `json:"session_id,omitempty"`
	Hostname    string   `json:"hostname"`
	Domain      string   `json:"domain"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	Version     string   `json:"version"`
	RemoteIP    string   `json:"remote_ip"`
	Status      string   `json:"status"` // "online"
	ConnectedAt string   `json:"connected_at"`
	LastSeen    string   `json:"last_seen"`
	Uptime      string   `json:"uptime"`
	Tags        []string `json:"tags,omitempty"`
}

const (
	TypeCopyRequest EnvelopeType = "copy_request"
	TypeDNSQuery    EnvelopeType = "dns_query"
	TypeDNSResponse EnvelopeType = "dns_response"
	TypeNodeSync    EnvelopeType = "node_sync"
)

type NodeSync struct {
	Type  EnvelopeType   `json:"type"` // "node_sync"
	Nodes []NodeMetadata `json:"nodes"`
}

type DNSQuery struct {
	Type      EnvelopeType `json:"type"` // "dns_query"
	SessionID string       `json:"session_id"`
	Name      string       `json:"name"`
	QType     uint16       `json:"qtype"`
	Data      string       `json:"data"` // Base64 encoded RFC 1035 query wire data
}

type DNSResponse struct {
	Type      EnvelopeType `json:"type"` // "dns_response"
	SessionID string       `json:"session_id"`
	RCode     int          `json:"rcode"`
	TTL       uint32       `json:"ttl"`
	Data      string       `json:"data"` // Base64 encoded wire response
}

type CopyRequest struct {
	Type           EnvelopeType `json:"type"` // "copy_request"
	TransferID     string       `json:"transfer_id"`
	TargetHostname string       `json:"target_hostname"`
	Direction      string       `json:"direction"` // "upload" or "download"
	RemotePath     string       `json:"remote_path"`
}
