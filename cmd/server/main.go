package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"fabric/internal/server"
)

func main() {
	defaultDomain := os.Getenv("FABRIC_DOMAIN")
	if defaultDomain == "" {
		defaultDomain = "fabric.mesh"
	}

	portEnv := os.Getenv("FABRIC_PORT")
	defaultPort := 8443
	if portEnv != "" {
		if p, err := strconv.Atoi(portEnv); err == nil {
			defaultPort = p
		}
	}

	portFlag := flag.Int("port", defaultPort, "Port for primary WSS / HTTPS TLS listener")
	domainFlag := flag.String("domain", defaultDomain, "Domain for the Fabric DNS server")
	publicDomainFlag := flag.String("public-domain", os.Getenv("FABRIC_PUBLIC_DOMAIN"), "Public domain for ACME TLS certificates (e.g. example.com)")
	acmeEmailFlag := flag.String("acme-email", os.Getenv("FABRIC_ACME_EMAIL"), "Email address for Let's Encrypt ACME registration")
	acmeStagingFlag := flag.Bool("acme-staging", os.Getenv("FABRIC_ACME_STAGING") == "true", "Use Let's Encrypt staging environment")
	tlsPortFlag := flag.Int("tls-port", 0, "Secondary port for HTTPS/WSS TLS listener (optional)")
	httpPortFlag := flag.Int("http-port", 0, "Port for HTTP / ACME HTTP-01 challenge redirector (0 to disable)")
	caDirFlag := flag.String("ca-dir", "", "Directory to store internal Root CA")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	adminTokenFlag := flag.String("admin-token", os.Getenv("FABRIC_ADMIN_TOKEN"), "Pre-shared token for administrative control plane operations")
	gatewayIDFlag := flag.String("gateway-id", os.Getenv("FABRIC_GATEWAY_ID"), "Unique gateway identifier for federation")
	regionFlag := flag.String("region", os.Getenv("FABRIC_REGION"), "Geographic region for this gateway (e.g. us-east, eu-west)")
	federationCAFlag := flag.String("federation-ca", os.Getenv("FABRIC_FEDERATION_CA"), "Path to shared Federation Root CA certificate")
	peerFlag := flag.String("peer", os.Getenv("FABRIC_PEERS"), "Comma-separated list of peer gateway URLs to connect to")
	leafOfFlag := flag.String("leaf-of", os.Getenv("FABRIC_LEAF_OF"), "Core gateway URL to connect to as an outbound Leaf relay")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
	}

	var initialPeers []string
	if *peerFlag != "" {
		for _, p := range strings.Split(*peerFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				initialPeers = append(initialPeers, p)
			}
		}
	}

	srv, err := server.New(server.Config{
		Port:         *portFlag,
		Domain:       *domainFlag,
		PublicDomain: *publicDomainFlag,
		ACMEEmail:    *acmeEmailFlag,
		ACMEStaging:  *acmeStagingFlag,
		TLSPort:      *tlsPortFlag,
		HTTPPort:     *httpPortFlag,
		CADir:        *caDirFlag,
		Token:        token,
		AdminToken:   *adminTokenFlag,
		GatewayID:    *gatewayIDFlag,
		Region:       *regionFlag,
		FederationCA: *federationCAFlag,
		Peers:        initialPeers,
		LeafOf:       *leafOfFlag,
	})
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("Server fatal error: %v", err)
	}
}
