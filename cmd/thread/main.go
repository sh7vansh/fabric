package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"fabric/internal/agent"
)

func main() {
	defaultURL := os.Getenv("FABRIC_SERVER_URL")
	if defaultURL == "" {
		defaultURL = os.Getenv("FABRIC_SOCKET_URL")
	}
	if defaultURL == "" {
		defaultURL = os.Getenv("FABRIC_HOST")
	}
	if defaultURL == "" && os.Getenv("FABRIC_LISTEN") == "" {
		defaultURL = "ws://localhost:8080/ws"
	}

	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	defaultMode := os.Getenv("FABRIC_MODE")
	if defaultMode == "" {
		defaultMode = "local"
	}

	serverURL := flag.String("url", defaultURL, "Fabric Server WebSocket URL (ws:// or wss://)")
	modeFlag := flag.String("mode", defaultMode, "Operating mode: 'local' (default) or 'remote'")
	listenFlag := flag.String("listen", os.Getenv("FABRIC_LISTEN"), "Local address to listen on for direct remote connection mode (e.g. :8443)")
	domainFlag := flag.String("domain", defaultDomain, "Domain to register with the Fabric")
	caCertFlag := flag.String("ca-cert", os.Getenv("FABRIC_CA_CERT"), "Path to custom Root CA certificate")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	tagsFlag := flag.String("tags", os.Getenv("FABRIC_TAGS"), "Comma-separated metadata tags (e.g. web,prod)")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
	}

	mode := strings.ToLower(strings.TrimSpace(*modeFlag))
	if mode == "" {
		mode = "local"
	}

	listenAddr := *listenFlag
	if mode == "remote" && listenAddr == "" {
		listenAddr = ":8443"
	}

	var tags []string
	if *tagsFlag != "" {
		for _, t := range strings.Split(*tagsFlag, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	th := agent.New(agent.Config{
		ServerURL:     *serverURL,
		ListenAddress: listenAddr,
		Domain:        *domainFlag,
		CACertPath:    *caCertFlag,
		Token:         token,
		Tags:          tags,
	})

	if err := th.Run(ctx); err != nil {
		log.Fatalf("Thread daemon fatal error: %v", err)
	}
}
