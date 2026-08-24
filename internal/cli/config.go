package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	Host  string
	Token string
}

type FileConfig struct {
	CurrentContext string `json:"current_context"`
	Contexts       map[string]struct {
		Host  string `json:"host"`
		Token string `json:"token"`
	} `json:"contexts"`
}

func LoadConfig(hostFlag, tokenFlag string) *Config {
	cfg := &Config{
		Host:  "ws://localhost:8080/ws",
		Token: "default-secret",
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
				}
			}
		}
	}

	if envHost := os.Getenv("FABRIC_HOST"); envHost != "" {
		cfg.Host = envHost
	}
	if envToken := os.Getenv("FABRIC_TOKEN"); envToken != "" {
		cfg.Token = envToken
	}

	if hostFlag != "" {
		cfg.Host = hostFlag
	}
	if tokenFlag != "" {
		cfg.Token = tokenFlag
	}

	return cfg
}
