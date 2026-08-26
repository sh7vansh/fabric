package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func parseEnvFile(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	res := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, `"'`)
			res[k] = v
		}
	}
	return res
}

// DirectNodeEntry stores registration metadata for an inverted mode node.
type DirectNodeEntry struct {
	Address      string    `json:"address"`
	Hostname     string    `json:"hostname,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	OS           string    `json:"os,omitempty"`
	Arch         string    `json:"arch,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

type ContextConfig struct {
	Host        string                     `json:"host"`
	Token       string                     `json:"token"`
	CACert      string                     `json:"ca_cert,omitempty"`
	DirectNodes map[string]DirectNodeEntry `json:"direct_nodes,omitempty"`
}

type Config struct {
	Host          string
	Token         string
	CACert        string
	DirectAddress string
	DirectNodes   map[string]DirectNodeEntry
	ThreadName    string
}

type FileConfig struct {
	CurrentContext string                     `json:"current_context"`
	Contexts       map[string]ContextConfig   `json:"contexts"`
	DirectNodes    map[string]DirectNodeEntry `json:"direct_nodes,omitempty"`
}

func LoadConfig(hostFlag, tokenFlag, directFlag string, caCertFlag ...string) *Config {
	cfg := &Config{
		Host:        "wss://localhost:8443/ws",
		Token:       "default-secret",
		DirectNodes: make(map[string]DirectNodeEntry),
	}

	home, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(home, ".fabric", "config.json")
		b, err := os.ReadFile(configPath)
		if err == nil {
			var fileCfg FileConfig
			if err := json.Unmarshal(b, &fileCfg); err == nil {
				ctxName := fileCfg.CurrentContext
				if ctxName == "" {
					ctxName = "default"
				}
				if ctx, ok := fileCfg.Contexts[ctxName]; ok {
					if ctx.Host != "" {
						cfg.Host = ctx.Host
					}
					if ctx.Token != "" {
						cfg.Token = ctx.Token
					}
					if ctx.CACert != "" {
						cfg.CACert = ctx.CACert
					}
					if ctx.DirectNodes != nil {
						for k, v := range ctx.DirectNodes {
							cfg.DirectNodes[k] = v
						}
					}
				}
				if fileCfg.DirectNodes != nil {
					for k, v := range fileCfg.DirectNodes {
						if _, exists := cfg.DirectNodes[k]; !exists {
							cfg.DirectNodes[k] = v
						}
					}
				}
			}
		}
	}

	// Fallback to local daemon environment files if present
	envCandidates := []string{
		"/etc/fabric/agent.env",
		"/etc/fabric/node.env",
		"/etc/fabric/server.env",
		"/etc/fabric/socket.env",
	}
	if home, err := os.UserHomeDir(); err == nil {
		envCandidates = append(envCandidates,
			filepath.Join(home, ".config", "fabric", "agent.env"),
			filepath.Join(home, ".config", "fabric", "node.env"),
			filepath.Join(home, ".config", "fabric", "server.env"),
			filepath.Join(home, ".config", "fabric", "socket.env"),
			filepath.Join(home, ".fabric", "agent.env"),
			filepath.Join(home, ".fabric", "node.env"),
			filepath.Join(home, ".fabric", "server.env"),
			filepath.Join(home, ".fabric", "socket.env"),
		)
	}
	for _, p := range envCandidates {
		envVars := parseEnvFile(p)
		if len(envVars) > 0 {
			if cfg.Host == "wss://localhost:8443/ws" {
				if sURL, ok := envVars["FABRIC_SERVER_URL"]; ok && sURL != "" {
					cfg.Host = sURL
				} else if sURL, ok := envVars["FABRIC_SOCKET_URL"]; ok && sURL != "" {
					cfg.Host = sURL
				} else if hURL, ok := envVars["FABRIC_HOST"]; ok && hURL != "" {
					cfg.Host = hURL
				}
			}
			if cfg.Token == "default-secret" {
				if tok, ok := envVars["FABRIC_TOKEN"]; ok && tok != "" {
					cfg.Token = tok
				}
			}
			if cfg.CACert == "" {
				if ca, ok := envVars["FABRIC_CA_CERT"]; ok && ca != "" {
					cfg.CACert = ca
				}
			}
			if cfg.ThreadName == "" {
				if tn, ok := envVars["FABRIC_THREAD_NAME"]; ok && tn != "" {
					cfg.ThreadName = tn
				} else if nn, ok := envVars["FABRIC_NODE_NAME"]; ok && nn != "" {
					cfg.ThreadName = nn
				} else if ni, ok := envVars["FABRIC_NODE_ID"]; ok && ni != "" {
					cfg.ThreadName = ni
				}
			}
			break
		}
	}

	if envServer := os.Getenv("FABRIC_SERVER_URL"); envServer != "" {
		cfg.Host = envServer
	} else if envSocket := os.Getenv("FABRIC_SOCKET_URL"); envSocket != "" {
		cfg.Host = envSocket
	} else if envHost := os.Getenv("FABRIC_HOST"); envHost != "" {
		cfg.Host = envHost
	}

	if envThread := os.Getenv("FABRIC_THREAD_NAME"); envThread != "" {
		cfg.ThreadName = envThread
	} else if envNode := os.Getenv("FABRIC_NODE_NAME"); envNode != "" {
		cfg.ThreadName = envNode
	} else if envNodeID := os.Getenv("FABRIC_NODE_ID"); envNodeID != "" {
		cfg.ThreadName = envNodeID
	}

	if envToken := os.Getenv("FABRIC_TOKEN"); envToken != "" {
		cfg.Token = envToken
	}
	if envCA := os.Getenv("FABRIC_CA_CERT"); envCA != "" {
		cfg.CACert = envCA
	}

	if hostFlag != "" {
		cfg.Host = hostFlag
	}
	if tokenFlag != "" {
		cfg.Token = tokenFlag
	}
	if len(caCertFlag) > 0 && caCertFlag[0] != "" {
		cfg.CACert = caCertFlag[0]
	}
	if directFlag != "" {
		cfg.DirectAddress = directFlag
	}

	return cfg
}

func SaveConfig(cfg *Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	fabricDir := filepath.Join(home, ".fabric")
	if err := os.MkdirAll(fabricDir, 0755); err != nil {
		return err
	}

	configPath := filepath.Join(fabricDir, "config.json")
	var fileCfg FileConfig
	if b, err := os.ReadFile(configPath); err == nil {
		_ = json.Unmarshal(b, &fileCfg)
	}

	if fileCfg.Contexts == nil {
		fileCfg.Contexts = make(map[string]ContextConfig)
	}

	ctxName := fileCfg.CurrentContext
	if ctxName == "" {
		ctxName = "default"
		fileCfg.CurrentContext = ctxName
	}

	ctx := fileCfg.Contexts[ctxName]
	ctx.Host = cfg.Host
	ctx.Token = cfg.Token
	ctx.CACert = cfg.CACert
	ctx.DirectNodes = cfg.DirectNodes
	fileCfg.Contexts[ctxName] = ctx
	fileCfg.DirectNodes = cfg.DirectNodes

	b, err := json.MarshalIndent(fileCfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, b, 0600)
}

// RegisterDirectNode records an inverted mode node into local direct registry config.
func RegisterDirectNode(name, address string, tags []string, extra ...string) error {
	cfg := GetConfig()
	if cfg.DirectNodes == nil {
		cfg.DirectNodes = make(map[string]DirectNodeEntry)
	}
	hasInvertedTag := false
	for _, t := range tags {
		if t == "inverted" {
			hasInvertedTag = true
			break
		}
	}
	if !hasInvertedTag {
		tags = append(tags, "inverted")
	}

	hostname := name
	domain := "fabric.mesh"
	osName := "linux"
	arch := ""
	if len(extra) > 0 && extra[0] != "" {
		hostname = extra[0]
	}
	if len(extra) > 1 && extra[1] != "" {
		domain = extra[1]
	}
	if len(extra) > 2 && extra[2] != "" {
		osName = extra[2]
	}
	if len(extra) > 3 && extra[3] != "" {
		arch = extra[3]
	}

	cfg.DirectNodes[name] = DirectNodeEntry{
		Address:      address,
		Hostname:     hostname,
		Domain:       domain,
		OS:           osName,
		Arch:         arch,
		Tags:         tags,
		RegisteredAt: time.Now().UTC(),
	}
	return SaveConfig(cfg)
}

// LookupDirectNode retrieves a registered direct node from configuration.
func LookupDirectNode(hostname string) (DirectNodeEntry, bool) {
	cfg := GetConfig()
	if cfg == nil || cfg.DirectNodes == nil {
		return DirectNodeEntry{}, false
	}
	entry, ok := cfg.DirectNodes[hostname]
	return entry, ok
}


