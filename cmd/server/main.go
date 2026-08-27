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

	wgPortEnv := os.Getenv("FABRIC_WIREGUARD_PORT")
	defaultWGPort := 51820
	if wgPortEnv != "" {
		if p, err := strconv.Atoi(wgPortEnv); err == nil {
			defaultWGPort = p
		}
	}

	wgSubnetEnv := os.Getenv("FABRIC_WIREGUARD_SUBNET")
	if wgSubnetEnv == "" {
		wgSubnetEnv = "100.64.0.0/10"
	}

	portFlag := flag.Int("port", defaultPort, "Port for primary WSS / HTTPS TLS listener")
	domainFlag := flag.String("domain", defaultDomain, "Domain for the Fabric DNS server")
	publicDomainFlag := flag.String("public-domain", os.Getenv("FABRIC_PUBLIC_DOMAIN"), "Public domain for ACME TLS certificates (e.g. example.com)")
	acmeEmailFlag := flag.String("acme-email", os.Getenv("FABRIC_ACME_EMAIL"), "Email address for Let's Encrypt ACME registration")
	acmeStagingFlag := flag.Bool("acme-staging", os.Getenv("FABRIC_ACME_STAGING") == "true", "Use Let's Encrypt staging environment")
	serverIDEnv := os.Getenv("FABRIC_SERVER_ID")
	if serverIDEnv == "" {
		serverIDEnv = os.Getenv("FABRIC_GATEWAY_ID")
	}

	serverIDFlag := flag.String("server-id", serverIDEnv, "Unique server identifier for federation")
	gatewayIDFlag := flag.String("gateway-id", "", "[Deprecated] Unique gateway identifier for federation")
	httpPortFlag := flag.Int("http-port", 0, "Port for HTTP / ACME HTTP-01 challenge redirector (0 to disable)")
	caDirFlag := flag.String("ca-dir", "", "Directory to store internal Root CA")
	tokenFlag := flag.String("token", os.Getenv("FABRIC_TOKEN"), "Pre-shared token for authentication")
	adminTokenFlag := flag.String("admin-token", os.Getenv("FABRIC_ADMIN_TOKEN"), "Pre-shared token for administrative control plane operations")
	regionFlag := flag.String("region", os.Getenv("FABRIC_REGION"), "Geographic region for this server (e.g. us-east, eu-west)")
	federationCAFlag := flag.String("federation-ca", os.Getenv("FABRIC_FEDERATION_CA"), "Path to shared Federation Root CA certificate")
	peerFlag := flag.String("peer", os.Getenv("FABRIC_PEERS"), "Comma-separated list of peer server URLs to connect to")
	leafOfFlag := flag.String("leaf-of", os.Getenv("FABRIC_LEAF_OF"), "Core server URL to connect to as an outbound Leaf relay")

	// WireGuard Gateway configuration flags
	wgPortFlag := flag.Int("wireguard-port", defaultWGPort, "UDP port for embedded WireGuard gateway listener")
	wgSubnetFlag := flag.String("wireguard-subnet", wgSubnetEnv, "Overlay CIDR subnet (default 100.64.0.0/10)")
	noWGFlag := flag.Bool("no-wireguard", os.Getenv("FABRIC_WIREGUARD_DISABLED") == "true", "Disable embedded WireGuard gateway")
	wgKeyFlag := flag.String("wireguard-key", os.Getenv("FABRIC_WIREGUARD_KEY"), "Path to WireGuard private key or base64 key string")
	wgDevicesFlag := flag.String("wireguard-devices", os.Getenv("FABRIC_WIREGUARD_DEVICES"), "Path to devices.json persistence file")
	wgEndpointFlag := flag.String("wireguard-endpoint", os.Getenv("FABRIC_WIREGUARD_ENDPOINT"), "Public WireGuard endpoint override (host:port)")

	flag.Parse()

	token := *tokenFlag
	if token == "" {
		log.Fatal("Authentication token required: set FABRIC_TOKEN environment variable or pass --token")
	}

	effectiveServerID := *serverIDFlag
	if effectiveServerID == "" {
		effectiveServerID = *gatewayIDFlag
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
		Port:              *portFlag,
		Domain:            *domainFlag,
		PublicDomain:      *publicDomainFlag,
		ACMEEmail:         *acmeEmailFlag,
		ACMEStaging:       *acmeStagingFlag,
		HTTPPort:          *httpPortFlag,
		CADir:             *caDirFlag,
		Token:             token,
		AdminToken:        *adminTokenFlag,
		ServerID:          effectiveServerID,
		GatewayID:         effectiveServerID,
		Region:            *regionFlag,
		FederationCA:      *federationCAFlag,
		Peers:             initialPeers,
		LeafOf:            *leafOfFlag,
		WireGuardPort:     *wgPortFlag,
		WireGuardSubnet:   *wgSubnetFlag,
		WireGuardDisabled: *noWGFlag,
		WireGuardKeyPath:  *wgKeyFlag,
		WireGuardDevices:  *wgDevicesFlag,
		WireGuardEndpoint: *wgEndpointFlag,
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
