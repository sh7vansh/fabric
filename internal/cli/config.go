package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

// DirectThreadEntry stores registration metadata for an inverted mode thread.
type DirectThreadEntry struct {
	Address      string    `json:"address"`
	Hostname     string    `json:"hostname,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	OS           string    `json:"os,omitempty"`
	Arch         string    `json:"arch,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

// DirectNodeEntry is a backward-compatible alias for DirectThreadEntry.
type DirectNodeEntry = DirectThreadEntry

type ContextConfig struct {
	Host          string                       `json:"host"`
	Token         string                       `json:"token"`
	CACert        string                       `json:"ca_cert,omitempty"`
	DirectThreads map[string]DirectThreadEntry `json:"direct_threads,omitempty"`
	DirectNodes   map[string]DirectNodeEntry   `json:"direct_nodes,omitempty"`
}

type Config struct {
	Host          string
	Token         string
	CACert        string
	DirectAddress string
	DirectThreads map[string]DirectThreadEntry
	DirectNodes   map[string]DirectNodeEntry
	ThreadName    string
}

type FileConfig struct {
	CurrentContext string                       `json:"current_context"`
	Contexts       map[string]ContextConfig     `json:"contexts"`
	DirectThreads  map[string]DirectThreadEntry `json:"direct_threads,omitempty"`
	DirectNodes    map[string]DirectNodeEntry   `json:"direct_nodes,omitempty"`
}

func LoadConfig(hostFlag, tokenFlag, directFlag string, caCertFlag ...string) *Config {
	cfg := &Config{
		Host:          "wss://localhost:8443/ws",
		Token:         "default-secret",
		DirectThreads: make(map[string]DirectThreadEntry),
		DirectNodes:   make(map[string]DirectNodeEntry),
	}

	var configFiles []string
	if home, err := os.UserHomeDir(); err == nil {
		configFiles = append(configFiles, filepath.Join(home, ".fabric", "config.json"))
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		sudoHome := os.Getenv("SUDO_HOME")
		if sudoHome == "" {
			sudoHome = filepath.Join("/home", sudoUser)
		}
		configFiles = append(configFiles, filepath.Join(sudoHome, ".fabric", "config.json"))
	}
	sysDir := "/etc/fabric"
	if envSys := os.Getenv("FABRIC_SYS_CONFIG_DIR"); envSys != "" {
		sysDir = envSys
	}
	configFiles = append(configFiles, filepath.Join(sysDir, "config.json"))

	for _, configPath := range configFiles {
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
					if ctx.DirectThreads != nil {
						for k, v := range ctx.DirectThreads {
							cfg.DirectThreads[k] = v
							cfg.DirectNodes[k] = v
						}
					}
					if ctx.DirectNodes != nil {
						for k, v := range ctx.DirectNodes {
							cfg.DirectThreads[k] = v
							cfg.DirectNodes[k] = v
						}
					}
				}
				if fileCfg.DirectThreads != nil {
					for k, v := range fileCfg.DirectThreads {
						if _, exists := cfg.DirectThreads[k]; !exists {
							cfg.DirectThreads[k] = v
							cfg.DirectNodes[k] = v
						}
					}
				}
				if fileCfg.DirectNodes != nil {
					for k, v := range fileCfg.DirectNodes {
						if _, exists := cfg.DirectNodes[k]; !exists {
							cfg.DirectThreads[k] = v
							cfg.DirectNodes[k] = v
						}
					}
				}
				break
			}
		}
	}

	// Fallback to local daemon environment files if present
	envCandidates := []string{
		filepath.Join(sysDir, "agent.env"),
		filepath.Join(sysDir, "node.env"),
		filepath.Join(sysDir, "server.env"),
		filepath.Join(sysDir, "socket.env"),
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
	var targetDirs []string
	home, err := os.UserHomeDir()
	if err == nil {
		targetDirs = append(targetDirs, filepath.Join(home, ".fabric"))
	}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		sudoHome := os.Getenv("SUDO_HOME")
		if sudoHome == "" {
			sudoHome = filepath.Join("/home", sudoUser)
		}
		targetDirs = append(targetDirs, filepath.Join(sudoHome, ".fabric"))
	}

	if os.Geteuid() == 0 {
		targetDirs = append(targetDirs, "/etc/fabric")
	}

	var firstErr error
	for _, fabricDir := range targetDirs {
		_ = os.MkdirAll(fabricDir, 0755)
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
		if cfg.DirectThreads != nil {
			ctx.DirectThreads = cfg.DirectThreads
			ctx.DirectNodes = cfg.DirectThreads
			fileCfg.DirectThreads = cfg.DirectThreads
			fileCfg.DirectNodes = cfg.DirectThreads
		} else if cfg.DirectNodes != nil {
			ctx.DirectThreads = cfg.DirectNodes
			ctx.DirectNodes = cfg.DirectNodes
			fileCfg.DirectThreads = cfg.DirectNodes
			fileCfg.DirectNodes = cfg.DirectNodes
		}
		fileCfg.Contexts[ctxName] = ctx

		b, err := json.MarshalIndent(fileCfg, "", "  ")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		if err := os.WriteFile(configPath, b, 0644); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}

		if sudoUIDStr := os.Getenv("SUDO_UID"); sudoUIDStr != "" {
			if uid, err := strconv.Atoi(sudoUIDStr); err == nil {
				gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
				_ = os.Chown(fabricDir, uid, gid)
				_ = os.Chown(configPath, uid, gid)
			}
		}
	}

	return firstErr
}

// RegisterDirectThread records a direct connection thread into local direct registry config.
func RegisterDirectThread(name, address string, tags []string, extra ...string) error {
	cfg := GetConfig()
	if cfg.DirectThreads == nil {
		cfg.DirectThreads = make(map[string]DirectThreadEntry)
	}
	if cfg.DirectNodes == nil {
		cfg.DirectNodes = make(map[string]DirectNodeEntry)
	}
	hasRemoteTag := false
	hasInvertedTag := false
	for _, t := range tags {
		if t == "remote" {
			hasRemoteTag = true
		}
		if t == "inverted" {
			hasInvertedTag = true
		}
	}
	if !hasRemoteTag {
		tags = append(tags, "remote")
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

	entry := DirectThreadEntry{
		Address:      address,
		Hostname:     hostname,
		Domain:       domain,
		OS:           osName,
		Arch:         arch,
		Tags:         tags,
		RegisteredAt: time.Now().UTC(),
	}
	cfg.DirectThreads[name] = entry
	cfg.DirectNodes[name] = entry
	return SaveConfig(cfg)
}

// RegisterDirectNode is a backward-compatible alias for RegisterDirectThread.
func RegisterDirectNode(name, address string, tags []string, extra ...string) error {
	return RegisterDirectThread(name, address, tags, extra...)
}

// LookupDirectThread retrieves a registered direct thread from configuration.
func LookupDirectThread(hostname string) (DirectThreadEntry, bool) {
	cfg := GetConfig()
	if cfg == nil {
		return DirectThreadEntry{}, false
	}
	if cfg.DirectThreads != nil {
		if entry, ok := cfg.DirectThreads[hostname]; ok {
			return entry, true
		}
	}
	if cfg.DirectNodes != nil {
		if entry, ok := cfg.DirectNodes[hostname]; ok {
			return entry, true
		}
	}
	return DirectThreadEntry{}, false
}

// LookupDirectNode is a backward-compatible alias for LookupDirectThread.
func LookupDirectNode(hostname string) (DirectNodeEntry, bool) {
	return LookupDirectThread(hostname)
}


