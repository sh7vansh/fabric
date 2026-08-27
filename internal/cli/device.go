package cli

import (
	"crypto/rand"
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
	deviceInspectFormatFlag string

	stitchDeviceQRFlag       bool
	stitchDeviceWebFlag      bool
	stitchDeviceOutFlag      string
	stitchDeviceEndpointFlag string
	stitchDevicePSKFlag      bool
)

var deviceCmd = &cobra.Command{
	Use:     "device",
	Short:   "Manage paired WireGuard consumer devices",
	GroupID: "network",
	Example: `  # List all paired WireGuard devices
  fabric device ls

  # Inspect a specific device
  fabric device inspect iphone

  # Remove/revoke a device
  fabric device rm iphone`,
}

var deviceLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List all paired WireGuard devices",
	Example: `  # Table view of active devices
  fabric device ls

  # JSON format
  fabric device ls --format json

  # Display only device names
  fabric device ls -q`,
	RunE: runDeviceLs,
}

var deviceInspectCmd = &cobra.Command{
	Use:   "inspect <device-name>",
	Short: "Inspect detailed WireGuard device telemetry",
	Args:  cobra.ExactArgs(1),
	Example: `  fabric device inspect iphone`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		client := NewClient(GetConfig())
		dev, err := client.GetDevice(name)
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		if deviceInspectFormatFlag == "json" || deviceInspectFormatFlag == "" {
			b, _ := json.MarshalIndent(dev, "", "  ")
			fmt.Fprintln(out, string(b))
			return nil
		}

		return nil
	},
}

var deviceRmCmd = &cobra.Command{
	Use:     "rm <device-name>",
	Aliases: []string{"remove", "revoke", "disconnect"},
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
	Short: "Pair a phone, tablet, or TV as a WireGuard device",
	Args:  cobra.ExactArgs(1),
	Example: `  # Stitch an iPhone with terminal QR code and web download portal
  fabric stitch device iphone

  # Stitch without web server, save profile to myphone.conf
  fabric stitch device iphone --web=false --out myphone.conf

  # Stitch specifying public WireGuard endpoint
  fabric stitch device living-room-tv --endpoint vpn.example.com:51820`,
	RunE: runStitchDevice,
}

func init() {
	deviceLsCmd.Flags().BoolVarP(&deviceQuietFlag, "quiet", "q", false, "Only display device names")
	deviceLsCmd.Flags().StringVar(&deviceLsFormatFlag, "format", "", "Output format ('json' or raw)")
	deviceInspectCmd.Flags().StringVar(&deviceInspectFormatFlag, "format", "", "Output format ('json' or raw)")

	deviceCmd.AddCommand(deviceLsCmd)
	deviceCmd.AddCommand(deviceInspectCmd)
	deviceCmd.AddCommand(deviceRmCmd)

	stitchDeviceCmd.Flags().BoolVar(&stitchDeviceQRFlag, "qr", true, "Render ASCII QR code in terminal")
	stitchDeviceCmd.Flags().BoolVar(&stitchDeviceWebFlag, "web", true, "Serve temporary local web portal for mobile pairing")
	stitchDeviceCmd.Flags().StringVarP(&stitchDeviceOutFlag, "out", "o", "", "Path to write WireGuard .conf file (default <name>.conf)")
	stitchDeviceCmd.Flags().StringVar(&stitchDeviceEndpointFlag, "endpoint", "", "WireGuard server endpoint override (host:port)")
	stitchDeviceCmd.Flags().BoolVar(&stitchDevicePSKFlag, "psk", true, "Generate symmetric preshared key for quantum resistance")

	rootCmd.AddCommand(deviceCmd)
	stitchCmd.AddCommand(stitchDeviceCmd)
}

func runDeviceLs(cmd *cobra.Command, args []string) error {
	defer func() {
		deviceQuietFlag = false
		deviceLsFormatFlag = ""
	}()

	client := NewClient(GetConfig())
	devices, err := client.ListDevices()
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if deviceLsFormatFlag == "json" {
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

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tVIRTUAL IP\tPUBLIC KEY\tLAST HANDSHAKE\tTRANSFER (RX / TX)")
	for _, d := range devices {
		hsStr := "never"
		if !d.LastHandshake.IsZero() {
			hsStr = time.Since(d.LastHandshake).Round(time.Second).String() + " ago"
		}
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
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivKey))
	sb.WriteString(fmt.Sprintf("Address = %s/10\n", clientIP))
	if dnsIP != "" {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", dnsIP))
	}
	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPubKey))
	if psk != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
	}
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", serverEndpoint))
	sb.WriteString("AllowedIPs = 100.64.0.0/10\n")
	sb.WriteString("PersistentKeepalive = 25\n")
	return sb.String()
}

func runStitchDevice(cmd *cobra.Command, args []string) error {
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
	wgConf := GenerateWGConfigString(clientPriv, reg.VirtualIP, reg.DNS, reg.ServerPublicKey, serverEndpoint, psk)

	outFile := stitchDeviceOutFlag
	if outFile == "" {
		outFile = name + ".conf"
	}

	if err := os.WriteFile(outFile, []byte(wgConf), 0600); err != nil {
		return fmt.Errorf("failed to save config to %s: %w", outFile, err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "\n==================================================")
	fmt.Fprintf(out, "    Device %q Paired Successfully!\n", name)
	fmt.Fprintln(out, "==================================================")
	fmt.Fprintf(out, "Virtual IP:       %s/10\n", reg.VirtualIP)
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

func startEphemeralWebPortal(name, pin, confContent, confFilename string) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return
	}
	port := ln.Addr().(*net.TCPAddr).Port

	localIP := getLocalOutboundIP()
	portalURL := fmt.Sprintf("http://%s:%d/pair/%s", localIP, port, name)

	fmt.Println("\n🌐 Ephemeral Pairing Portal:")
	fmt.Printf("  URL: %s\n", portalURL)
	fmt.Printf("  PIN: %s\n", pin)
	fmt.Println("  (Link expires automatically in 5 minutes)")

	pngQR, _ := qrcode.Encode(confContent, qrcode.Medium, 256)
	pngQRB64 := base64.StdEncoding.EncodeToString(pngQR)

	srv := &http.Server{}
	var once sync.Once
	stopPortal := func() {
		once.Do(func() {
			_ = srv.Close()
			_ = ln.Close()
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
  <p>Or download profile configuration:</p>
  <form method="POST">
    <div class="pin-box">PIN: {{.PIN}}</div>
    <input type="hidden" name="pin" value="{{.PIN}}" />
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
		_ = srv.Serve(ln)
	}()

	// Auto-expire after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		stopPortal()
	}()
}

func getLocalOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
