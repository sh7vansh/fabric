package protocol

import (
	"encoding/json"
	"regexp"
)

var rfc1123HostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// IsValidHostname validates that a hostname adheres strictly to RFC 1123 DNS character rules.
func IsValidHostname(name string) bool {
	return rfc1123HostnameRegex.MatchString(name)
}

type EnvelopeType string

const (
	TypeHandshake        EnvelopeType = "handshake"
	TypeExecRequest      EnvelopeType = "exec_request"
	TypeServerHello      EnvelopeType = "server_hello"
	TypeGatewayHello     EnvelopeType = "gateway_hello"
	TypeServerHeartbeat  EnvelopeType = "server_heartbeat"
	TypeGatewayHeartbeat EnvelopeType = "gateway_heartbeat"
	TypeThreadAdvertise  EnvelopeType = "thread_advertise"
	TypeThreadWithdraw   EnvelopeType = "thread_withdraw"
)

type Handshake struct {
	Type      EnvelopeType `json:"type"`
	SessionID string       `json:"session_id,omitempty"`
	Hostname  string       `json:"hostname"`
	Domain    string       `json:"domain,omitempty"`
	Token     string       `json:"token"`
	OS        string       `json:"os,omitempty"`
	Arch      string       `json:"arch,omitempty"`
	Version   string       `json:"version,omitempty"`
	Tags      []string     `json:"tags,omitempty"`
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
	Path           []string     `json:"path,omitempty"`
	Hops           int          `json:"hops,omitempty"`
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
	ServerID    string   `json:"server_id,omitempty"`
	GatewayID   string   `json:"gateway_id,omitempty"`
}

type ThreadMetadata = NodeMetadata

func (n *NodeMetadata) UnmarshalJSON(data []byte) error {
	type Alias NodeMetadata
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if n.ServerID == "" && n.GatewayID != "" {
		n.ServerID = n.GatewayID
	}
	if n.GatewayID == "" && n.ServerID != "" {
		n.GatewayID = n.ServerID
	}
	return nil
}

func (n NodeMetadata) MarshalJSON() ([]byte, error) {
	type Alias NodeMetadata
	if n.ServerID == "" && n.GatewayID != "" {
		n.ServerID = n.GatewayID
	}
	if n.GatewayID == "" && n.ServerID != "" {
		n.GatewayID = n.ServerID
	}
	return json.Marshal(Alias(n))
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
	Path           []string     `json:"path,omitempty"`
	Hops           int          `json:"hops,omitempty"`
}

type ServerHello struct {
	Type         EnvelopeType `json:"type"` // "server_hello" or "gateway_hello"
	ServerID     string       `json:"server_id,omitempty"`
	GatewayID    string       `json:"gateway_id,omitempty"`
	Domain       string       `json:"domain,omitempty"`
	Region       string       `json:"region,omitempty"`
	Capabilities []string     `json:"capabilities,omitempty"`
	Token        string       `json:"token,omitempty"`
	IsLeaf       bool         `json:"is_leaf,omitempty"`
}

type GatewayHello = ServerHello

func (s *ServerHello) UnmarshalJSON(data []byte) error {
	type Alias ServerHello
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if s.ServerID == "" && s.GatewayID != "" {
		s.ServerID = s.GatewayID
	}
	if s.GatewayID == "" && s.ServerID != "" {
		s.GatewayID = s.ServerID
	}
	return nil
}

func (s ServerHello) MarshalJSON() ([]byte, error) {
	type Alias ServerHello
	if s.Type == "" {
		s.Type = TypeServerHello
	}
	if s.ServerID == "" && s.GatewayID != "" {
		s.ServerID = s.GatewayID
	}
	if s.GatewayID == "" && s.ServerID != "" {
		s.GatewayID = s.ServerID
	}
	return json.Marshal(Alias(s))
}

type ServerHeartbeat struct {
	Type      EnvelopeType `json:"type"` // "server_heartbeat" or "gateway_heartbeat"
	ServerID  string       `json:"server_id,omitempty"`
	GatewayID string       `json:"gateway_id,omitempty"`
	Timestamp string       `json:"timestamp"`
}

type GatewayHeartbeat = ServerHeartbeat

func (s *ServerHeartbeat) UnmarshalJSON(data []byte) error {
	type Alias ServerHeartbeat
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if s.ServerID == "" && s.GatewayID != "" {
		s.ServerID = s.GatewayID
	}
	if s.GatewayID == "" && s.ServerID != "" {
		s.GatewayID = s.ServerID
	}
	return nil
}

func (s ServerHeartbeat) MarshalJSON() ([]byte, error) {
	type Alias ServerHeartbeat
	if s.Type == "" {
		s.Type = TypeServerHeartbeat
	}
	if s.ServerID == "" && s.GatewayID != "" {
		s.ServerID = s.GatewayID
	}
	if s.GatewayID == "" && s.ServerID != "" {
		s.GatewayID = s.ServerID
	}
	return json.Marshal(Alias(s))
}

type ServerPeerInfo struct {
	ServerID     string   `json:"server_id,omitempty"`
	GatewayID    string   `json:"gateway_id,omitempty"`
	Domain       string   `json:"domain"`
	Region       string   `json:"region"`
	Capabilities []string `json:"capabilities"`
	Status       string   `json:"status"`
	Topology     string   `json:"topology"` // "core" or "leaf"
	RTT          string   `json:"rtt"`
	ThreadCount  int      `json:"thread_count"`
	ConnectedAt  string   `json:"connected_at"`
	Endpoint     string   `json:"endpoint"`
}

type GatewayPeerInfo = ServerPeerInfo

func (s *ServerPeerInfo) UnmarshalJSON(data []byte) error {
	type Alias ServerPeerInfo
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if s.ServerID == "" && s.GatewayID != "" {
		s.ServerID = s.GatewayID
	}
	if s.GatewayID == "" && s.ServerID != "" {
		s.GatewayID = s.ServerID
	}
	return nil
}

func (s ServerPeerInfo) MarshalJSON() ([]byte, error) {
	type Alias ServerPeerInfo
	if s.ServerID == "" && s.GatewayID != "" {
		s.ServerID = s.GatewayID
	}
	if s.GatewayID == "" && s.ServerID != "" {
		s.GatewayID = s.ServerID
	}
	return json.Marshal(Alias(s))
}

type ThreadAdvertise struct {
	Type      EnvelopeType   `json:"type"` // "thread_advertise"
	ServerID  string         `json:"server_id,omitempty"`
	GatewayID string         `json:"gateway_id,omitempty"`
	Nodes     []NodeMetadata `json:"nodes"`
}

func (a *ThreadAdvertise) UnmarshalJSON(data []byte) error {
	type Alias ThreadAdvertise
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if a.ServerID == "" && a.GatewayID != "" {
		a.ServerID = a.GatewayID
	}
	if a.GatewayID == "" && a.ServerID != "" {
		a.GatewayID = a.ServerID
	}
	return nil
}

func (a ThreadAdvertise) MarshalJSON() ([]byte, error) {
	type Alias ThreadAdvertise
	if a.Type == "" {
		a.Type = TypeThreadAdvertise
	}
	if a.ServerID == "" && a.GatewayID != "" {
		a.ServerID = a.GatewayID
	}
	if a.GatewayID == "" && a.ServerID != "" {
		a.GatewayID = a.ServerID
	}
	return json.Marshal(Alias(a))
}

type ThreadWithdraw struct {
	Type      EnvelopeType `json:"type"` // "thread_withdraw"
	ServerID  string       `json:"server_id,omitempty"`
	GatewayID string       `json:"gateway_id,omitempty"`
	Hostname  string       `json:"hostname"`
}

func (w *ThreadWithdraw) UnmarshalJSON(data []byte) error {
	type Alias ThreadWithdraw
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(w),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if w.ServerID == "" && w.GatewayID != "" {
		w.ServerID = w.GatewayID
	}
	if w.GatewayID == "" && w.ServerID != "" {
		w.GatewayID = w.ServerID
	}
	return nil
}

func (w ThreadWithdraw) MarshalJSON() ([]byte, error) {
	type Alias ThreadWithdraw
	if w.Type == "" {
		w.Type = TypeThreadWithdraw
	}
	if w.ServerID == "" && w.GatewayID != "" {
		w.ServerID = w.GatewayID
	}
	if w.GatewayID == "" && w.ServerID != "" {
		w.GatewayID = w.ServerID
	}
	return json.Marshal(Alias(w))
}

