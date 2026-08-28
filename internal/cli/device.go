package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"fabric/internal/wireguard"

	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

var (
	deviceQuietFlag         bool
	deviceLsFormatFlag      string
	deviceLsOutputFlag      string
	deviceInspectFormatFlag string
	deviceInspectOutputFlag string

	stitchDeviceQRFlag       bool
	stitchDeviceWebFlag      bool
	stitchDeviceOutFlag      string
	stitchDeviceEndpointFlag string
	stitchDevicePSKFlag      bool
	stitchDeviceSubnetFlag   string
)

var deviceCmd = &cobra.Command{
	Use:     "device",
	Short:   "Manage paired WireGuard consumer devices",
	GroupID: "network",
	Example: `  # Add/pair a phone or laptop device
  fabric device add iphone

  # List all paired WireGuard devices
  fabric device ls

  # Inspect a specific device
  fabric device inspect iphone

  # Remove/revoke a device
  fabric device rm iphone`,
}

var deviceAddCmd = &cobra.Command{
	Use:     "add <name>",
	Aliases: []string{"create"},
	Short:   "Generate a WireGuard client profile, keys, and QR code for a device",
	Args:    cobra.ExactArgs(1),
	Example: `  # Add an iPhone with terminal QR code and web download portal
  fabric device add iphone

  # Add without web server, save profile to myphone.conf
  fabric device add iphone --web=false --out myphone.conf

  # Add specifying public WireGuard endpoint
  fabric device add living-room-tv --endpoint vpn.example.com:51820`,
	RunE: runStitchDevice,
}

var deviceLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List all paired WireGuard devices",
	Example: `  # Table view of active devices
  fabric device ls

  # JSON format
  fabric device ls -o json
  fabric device ls --format json

  # Display only device names
  fabric device ls -q`,
	RunE: runDeviceLs,
}

var deviceInspectCmd = &cobra.Command{
	Use:   "inspect <device-name>",
	Short: "Inspect detailed WireGuard device telemetry",
	Args:  cobra.ExactArgs(1),
	Example: `  # Inspect device in card view
  fabric device inspect iphone

  # Inspect in JSON format
  fabric device inspect -o json iphone`,
	RunE: func(cmd *cobra.Command, args []string) error {
		defer func() {
			deviceInspectFormatFlag = ""
			deviceInspectOutputFlag = ""
		}()

		name := args[0]
		client := NewClient(GetConfig())
		dev, err := client.GetDevice(name)
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		if strings.ToLower(deviceInspectFormatFlag) == "json" || strings.ToLower(deviceInspectOutputFlag) == "json" {
			b, _ := json.MarshalIndent(dev, "", "  ")
			fmt.Fprintln(out, string(b))
			return nil
		}

		fmt.Fprintln(out, "==================================================")
		fmt.Fprintf(out, "  Device: %s\n", dev.Name)
		fmt.Fprintln(out, "==================================================")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  Name:\t%s\n", dev.Name)
		fmt.Fprintf(w, "  Virtual IP:\t%s\n", dev.VirtualIP)
		fmt.Fprintf(w, "  Public Key:\t%s\n", dev.PublicKey)
		if dev.PresharedKey != "" {
			fmt.Fprintf(w, "  Preshared Key:\t[configured]\n")
		}
		fmt.Fprintf(w, "  Last Handshake:\t%s\n", formatRelativeTime(dev.LastHandshake))
		fmt.Fprintf(w, "  Transfer (RX / TX):\t%s / %s\n", formatBytes(dev.RxBytes), formatBytes(dev.TxBytes))
		if !dev.CreatedAt.IsZero() {
			fmt.Fprintf(w, "  Created At:\t%s (%s)\n", dev.CreatedAt.Format(time.RFC3339), formatRelativeTime(dev.CreatedAt))
		}
		w.Flush()
		fmt.Fprintln(out, "==================================================")
		return nil
	},
}

var deviceRmCmd = &cobra.Command{
	Use:     "rm <device-name>",
	Short:   "Revoke and remove a WireGuard device",
	Args:    cobra.ExactArgs(1),
	Example: `  fabric device rm iphone`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		client := NewClient(GetConfig())
		if err := client.RemoveDevice(name); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Successfully removed device %q\n", name)
		return nil
	},
}

var stitchDeviceCmd = &cobra.Command{
	Use:   "device <name>",
	Short: "Pair a phone, tablet, or TV as a WireGuard device (alias for 'fabric device add')",
	Args:  cobra.ExactArgs(1),
	Example: `  # Stitch an iPhone with terminal QR code and web download portal
  fabric stitch device iphone

  # Stitch without web server, save profile to myphone.conf
  fabric stitch device iphone --web=false --out myphone.conf

  # Stitch specifying public WireGuard endpoint
  fabric stitch device living-room-tv --endpoint vpn.example.com:51820`,
	RunE: runStitchDevice,
}

func registerDeviceAddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&stitchDeviceQRFlag, "qr", true, "Render ASCII QR code in terminal")
	cmd.Flags().BoolVar(&stitchDeviceWebFlag, "web", true, "Serve temporary local web portal for mobile pairing")
	cmd.Flags().StringVarP(&stitchDeviceOutFlag, "out", "o", "", "Path to write WireGuard .conf file (default <name>.conf)")
	cmd.Flags().StringVar(&stitchDeviceEndpointFlag, "endpoint", "", "WireGuard server endpoint override (host:port)")
	cmd.Flags().BoolVar(&stitchDevicePSKFlag, "psk", true, "Generate symmetric preshared key for quantum resistance")
	cmd.Flags().StringVar(&stitchDeviceSubnetFlag, "subnet", "", "Custom overlay subnet override (e.g. 10.42.0.0/16)")
}

func init() {
	deviceLsCmd.Flags().BoolVarP(&deviceQuietFlag, "quiet", "q", false, "Only display device names")
	deviceLsCmd.Flags().StringVarP(&deviceLsFormatFlag, "format", "f", "", "Output format ('json' or raw)")
	deviceLsCmd.Flags().StringVarP(&deviceLsOutputFlag, "output", "o", "", "Output format ('json' or table)")
	deviceInspectCmd.Flags().StringVarP(&deviceInspectFormatFlag, "format", "f", "", "Output format ('json' or card)")
	deviceInspectCmd.Flags().StringVarP(&deviceInspectOutputFlag, "output", "o", "", "Output format ('json' or card)")

	registerDeviceAddFlags(deviceAddCmd)
	registerDeviceAddFlags(stitchDeviceCmd)

	deviceCmd.AddCommand(deviceAddCmd)
	deviceCmd.AddCommand(deviceLsCmd)
	deviceCmd.AddCommand(deviceInspectCmd)
	deviceCmd.AddCommand(deviceRmCmd)

	rootCmd.AddCommand(deviceCmd)
	stitchCmd.AddCommand(stitchDeviceCmd)
}

func formatRelativeTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		if secs > 0 {
			return fmt.Sprintf("%dm%ds ago", mins, secs)
		}
		return fmt.Sprintf("%dm ago", mins)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		mins := int(d.Minutes()) % 60
		if mins > 0 {
			return fmt.Sprintf("%dh%dm ago", hours, mins)
		}
		return fmt.Sprintf("%dh ago", hours)
	}
	days := int(d.Hours()) / 24
	return fmt.Sprintf("%dd ago", days)
}

func runDeviceLs(cmd *cobra.Command, args []string) error {
	defer func() {
		deviceQuietFlag = false
		deviceLsFormatFlag = ""
		deviceLsOutputFlag = ""
	}()

	client := NewClient(GetConfig())
	devices, err := client.ListDevices()
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if strings.ToLower(deviceLsFormatFlag) == "json" || strings.ToLower(deviceLsOutputFlag) == "json" {
		b, _ := json.MarshalIndent(devices, "", "  ")
		fmt.Fprintln(out, string(b))
		return nil
	}

	if deviceQuietFlag {
		for _, d := range devices {
			fmt.Fprintln(out, d.Name)
		}
		return nil
	}

	if len(devices) == 0 {
		fmt.Fprintln(out, "No WireGuard devices registered.")
		fmt.Fprintln(out, "To pair a device (phone, laptop, tablet), run:")
		fmt.Fprintln(out, "  fabric device add <name>")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tVIRTUAL IP\tPUBLIC KEY\tLAST HANDSHAKE\tTRANSFER (RX / TX)")
	for _, d := range devices {
		hsStr := formatRelativeTime(d.LastHandshake)
		pubKeyShort := d.PublicKey
		if len(pubKeyShort) > 16 {
			pubKeyShort = pubKeyShort[:8] + "…" + pubKeyShort[len(pubKeyShort)-6:]
		}
		rxStr := formatBytes(d.RxBytes)
		txStr := formatBytes(d.TxBytes)
		transferStr := fmt.Sprintf("%s / %s", rxStr, txStr)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d.Name, d.VirtualIP, pubKeyShort, hsStr, transferStr)
	}
	w.Flush()
	return nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// GenerateWGConfigString formats standard WireGuard INI configuration.
func GenerateWGConfigString(clientPrivKey, clientIP, dnsIP, serverPubKey, serverEndpoint, psk string) string {
	return GenerateWGConfigStringWithSubnet(clientPrivKey, clientIP, dnsIP, serverPubKey, serverEndpoint, psk, "100.64.0.0/10")
}

// GenerateWGConfigStringWithSubnet formats standard WireGuard INI configuration with custom overlay subnet.
func GenerateWGConfigStringWithSubnet(clientPrivKey, clientIP, dnsIP, serverPubKey, serverEndpoint, psk, subnet string) string {
	if subnet == "" {
		subnet = "100.64.0.0/10"
	}
	mask := "10"
	if parts := strings.Split(subnet, "/"); len(parts) == 2 {
		mask = parts[1]
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivKey))
	sb.WriteString(fmt.Sprintf("Address = %s/%s\n", clientIP, mask))
	if dnsIP != "" {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", dnsIP))
	}
	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPubKey))
	if psk != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
	}
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", serverEndpoint))
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", subnet))
	sb.WriteString("PersistentKeepalive = 25\n")
	return sb.String()
}

func runStitchDevice(cmd *cobra.Command, args []string) error {
	defer func() {
		stitchDeviceSubnetFlag = ""
	}()

	name := strings.TrimSpace(args[0])
	if name == "" {
		return fmt.Errorf("device name cannot be empty")
	}

	client := NewClient(GetConfig())

	// 1. Generate client WireGuard keypair & optional PSK
	clientPriv, clientPub, err := wireguard.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate device keypair: %w", err)
	}

	var psk string
	if stitchDevicePSKFlag {
		psk, _ = wireguard.GeneratePresharedKey()
	}

	// 2. Register with server control-plane
	reg, err := client.RegisterDevice(name, clientPub, psk)
	if err != nil {
		return err
	}

	serverEndpoint := reg.ServerEndpoint
	if stitchDeviceEndpointFlag != "" {
		serverEndpoint = stitchDeviceEndpointFlag
	}

	// 3. Generate WireGuard profile configuration
	subnet := stitchDeviceSubnetFlag
	if subnet == "" {
		subnet = "100.64.0.0/10"
	}
	wgConf := GenerateWGConfigStringWithSubnet(clientPriv, reg.VirtualIP, reg.DNS, reg.ServerPublicKey, serverEndpoint, psk, subnet)

	outFile := stitchDeviceOutFlag
	if outFile == "" {
		outFile = name + ".conf"
	}

	if err := os.WriteFile(outFile, []byte(wgConf), 0600); err != nil {
		return fmt.Errorf("failed to save config to %s: %w", outFile, err)
	}

	mask := "10"
	if parts := strings.Split(subnet, "/"); len(parts) == 2 {
		mask = parts[1]
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "\n==================================================")
	fmt.Fprintf(out, "    Device %q Paired Successfully!\n", name)
	fmt.Fprintln(out, "==================================================")
	fmt.Fprintf(out, "Virtual IP:       %s/%s\n", reg.VirtualIP, mask)
	fmt.Fprintf(out, "DNS Gateway:      %s\n", reg.DNS)
	fmt.Fprintf(out, "Server Endpoint:  %s\n", serverEndpoint)
	fmt.Fprintf(out, "Config File:      %s\n", outFile)
	fmt.Fprintln(out, "==================================================")

	// 4. Render Terminal ASCII QR Code
	if stitchDeviceQRFlag {
		fmt.Fprintln(out, "\nScan this QR code with WireGuard on iOS/Android:")
		qrObj, qrErr := qrcode.New(wgConf, qrcode.Medium)
		if qrErr == nil {
			fmt.Fprintln(out, qrObj.ToSmallString(false))
		}
	}

	// 5. Ephemeral Local Web Portal for one-click pairing
	if stitchDeviceWebFlag {
		pin, _ := generatePin()
		startEphemeralWebPortal(name, pin, wgConf, outFile)
	}

	return nil
}

func generatePin() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "123456", err
	}
	return fmt.Sprintf("%06d", n.Int64()+100000), nil
}

func generateEphemeralTLSCert(ips ...net.IP) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	validIPs := []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
	for _, ip := range ips {
		if ip != nil {
			validIPs = append(validIPs, ip)
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Fabric Ephemeral Pairing Portal",
			Organization: []string{"Fabric"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           validIPs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// EphemeralPortal represents a running TLS pairing web portal.
type EphemeralPortal struct {
	URL      string
	Server   *http.Server
	Listener net.Listener
	Stop     func()
}

// StartEphemeralWebPortal spawns a TLS-encrypted ephemeral web portal for onboarding headless/TV devices.
func StartEphemeralWebPortal(name, pin, confContent, confFilename string) (*EphemeralPortal, error) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind ephemeral port: %w", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	localIP := getLocalOutboundIP()

	tlsCert, err := generateEphemeralTLSCert(net.ParseIP(localIP))
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to generate ephemeral TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsLn := tls.NewListener(ln, tlsConfig)

	portalURL := fmt.Sprintf("https://%s:%d/pair/%s", localIP, port, name)

	pngQR, _ := qrcode.Encode(confContent, qrcode.Medium, 256)
	pngQRB64 := base64.StdEncoding.EncodeToString(pngQR)

	srv := &http.Server{}
	var once sync.Once
	stopPortal := func() {
		once.Do(func() {
			_ = srv.Close()
			_ = tlsLn.Close()
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pair/"+name, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			enteredPin := strings.TrimSpace(r.FormValue("pin"))
			if enteredPin != pin {
				http.Error(w, "Invalid PIN code", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(confFilename)))
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, confContent)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl := `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pair Device - {{.Name}}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 16px; }
.card { background: #1e293b; border-radius: 16px; padding: 24px; max-width: 380px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; border: 1px solid #334155; }
h1 { font-size: 20px; margin-bottom: 8px; color: #38bdf8; }
p { color: #94a3b8; font-size: 14px; margin-top: 0; }
.qr { background: #fff; padding: 12px; border-radius: 12px; display: inline-block; margin: 16px 0; }
.qr img { display: block; max-width: 100%; height: auto; }
.pin-box { background: #0f172a; border-radius: 8px; padding: 8px 16px; font-size: 22px; font-weight: bold; letter-spacing: 4px; color: #a855f7; margin: 12px 0; }
button { background: #2563eb; color: #fff; border: none; border-radius: 8px; padding: 10px 18px; font-weight: 600; cursor: pointer; width: 100%; font-size: 15px; margin-top: 8px; }
button:hover { background: #1d4ed8; }
</style>
</head>
<body>
<div class="card">
  <h1>Fabric Device Pairing</h1>
  <p>Scan with WireGuard on <strong>{{.Name}}</strong></p>
  <div class="qr"><img src="data:image/png;base64,{{.QRB64}}" alt="WireGuard QR Code" /></div>
  <p>Or enter pairing PIN to download configuration:</p>
  <form method="POST">
    <input type="text" name="pin" placeholder="Enter 6-digit PIN" maxlength="6" autocomplete="off" required style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 10px; font-size: 18px; text-align: center; color: #f8fafc; letter-spacing: 4px; width: 100%; box-sizing: border-box; margin-bottom: 10px;" />
    <button type="submit">Download {{.Name}}.conf</button>
  </form>
</div>
</body>
</html>`
		t, _ := template.New("portal").Parse(tmpl)
		_ = t.Execute(w, map[string]string{
			"Name":  name,
			"QRB64": pngQRB64,
			"PIN":   pin,
		})
	})

	srv.Handler = mux

	go func() {
		_ = srv.Serve(tlsLn)
	}()

	// Auto-expire after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		stopPortal()
	}()

	return &EphemeralPortal{
		URL:      portalURL,
		Server:   srv,
		Listener: tlsLn,
		Stop:     stopPortal,
	}, nil
}

func startEphemeralWebPortal(name, pin, confContent, confFilename string) {
	portal, err := StartEphemeralWebPortal(name, pin, confContent, confFilename)
	if err != nil {
		fmt.Printf("⚠️ Failed to start ephemeral pairing web portal: %v\n", err)
		return
	}

	fmt.Println("\n🌐 Ephemeral Pairing Portal (TLS):")
	fmt.Printf("  URL: %s\n", portal.URL)
	fmt.Printf("  PIN: %s\n", pin)
	fmt.Println("  (Link expires automatically in 5 minutes)")
}

func getLocalOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
