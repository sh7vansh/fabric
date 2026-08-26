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
		defaultURL = "wss://localhost:8443/ws"
	}

	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	serverURL := flag.String("url", defaultURL, "Socket URL (wss://)")
	listenFlag := flag.String("listen", os.Getenv("FABRIC_LISTEN"), "Local address to listen on for inverted connection mode (e.g. :8443)")
	domainFlag := flag.String("domain", defaultDomain, "Domain to register with the mesh")
	caCertFlag := flag.String("ca-cert", os.Getenv("FABRIC_CA_CERT"), "Path to custom Root CA certificate")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	tagsFlag := flag.String("tags", os.Getenv("FABRIC_TAGS"), "Comma-separated metadata tags (e.g. web,prod)")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
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

	ag := agent.New(agent.Config{
		ServerURL:     *serverURL,
		ListenAddress: *listenFlag,
		Domain:        *domainFlag,
		CACertPath:    *caCertFlag,
		Token:         token,
		Tags:          tags,
	})

	if err := ag.Run(ctx); err != nil {
		log.Fatalf("Agent fatal error: %v", err)
	}
}
