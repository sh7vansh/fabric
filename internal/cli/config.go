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
	fileCfg := FileConfig{
		CurrentContext: "default",
		Contexts: map[string]struct {
			Host  string `json:"host"`
			Token string `json:"token"`
		}{
			"default": {
				Host:  cfg.Host,
				Token: cfg.Token,
			},
		},
	}

	b, err := json.MarshalIndent(fileCfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, b, 0600)
}

