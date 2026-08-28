package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fabric/internal/wireguard"
)

func TestDeviceCLICommands(t *testing.T) {
	devices := []wireguard.DeviceEntry{
		{
			Name:          "iphone-13",
			PublicKey:     "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF=",
			VirtualIP:     "100.64.128.1",
			RxBytes:       1048576,
			TxBytes:       2097152,
			LastHandshake: time.Now().Add(-2 * time.Minute),
			CreatedAt:     time.Now().Add(-24 * time.Hour),
		},
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if (r.URL.Path == "/api/v1/devices" || r.URL.Path == "/devices") && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(devices)
			return
		}
		if (r.URL.Path == "/api/v1/devices/iphone-13" || r.URL.Path == "/devices/iphone-13") && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(devices[0])
			return
		}
		if (r.URL.Path == "/api/v1/devices/iphone-13" || r.URL.Path == "/devices/iphone-13") && r.Method == http.MethodDelete {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "removed", "device": "iphone-13"})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("FABRIC_SYS_CONFIG_DIR", tmpDir)
	caFile := filepath.Join(tmpDir, "ca.crt")
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}
	_ = os.WriteFile(caFile, pem.EncodeToMemory(pemBlock), 0644)

	cfg := &Config{
		Host:   ts.URL,
		Token:  "test-token",
		CACert: caFile,
	}
	_ = SaveConfig(cfg)

	// 1. Test `fabric device ls`
	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"device", "ls"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device ls failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "iphone-13") || !strings.Contains(outStr, "100.64.128.1") {
		t.Errorf("expected table output to contain device info, got:\n%s", outStr)
	}

	// 2. Test `fabric device ls -q`
	outBuf.Reset()
	rootCmd.SetArgs([]string{"device", "ls", "-q"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device ls -q failed: %v", err)
	}
	if strings.TrimSpace(outBuf.String()) != "iphone-13" {
		t.Errorf("expected 'iphone-13', got %q", outBuf.String())
	}

	// 3. Test `fabric device ls --format json`
	outBuf.Reset()
	rootCmd.SetArgs([]string{"device", "ls", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device ls --format json failed: %v", err)
	}
	var resList []wireguard.DeviceEntry
	if err := json.Unmarshal(outBuf.Bytes(), &resList); err != nil || len(resList) != 1 {
		t.Errorf("invalid json output: %v", err)
	}

	// 4. Test `fabric device inspect iphone-13` (card view by default & json with -o json)
	outBuf.Reset()
	rootCmd.SetArgs([]string{"device", "inspect", "iphone-13"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device inspect failed: %v", err)
	}
	cardOut := outBuf.String()
	if !strings.Contains(cardOut, "Device: iphone-13") || !strings.Contains(cardOut, "Virtual IP:") {
		t.Errorf("expected human-readable card from inspect, got:\n%s", cardOut)
	}

	outBuf.Reset()
	rootCmd.SetArgs([]string{"device", "inspect", "-o", "json", "iphone-13"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device inspect -o json failed: %v", err)
	}
	var dev wireguard.DeviceEntry
	if err := json.Unmarshal(outBuf.Bytes(), &dev); err != nil || dev.Name != "iphone-13" {
		t.Errorf("invalid json from inspect: %v", err)
	}

	// 5. Test `fabric device rm iphone-13`
	outBuf.Reset()
	rootCmd.SetArgs([]string{"device", "rm", "iphone-13"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device rm failed: %v", err)
	}
	if !strings.Contains(outBuf.String(), "Successfully removed device") {
		t.Errorf("unexpected output from rm: %s", outBuf.String())
	}
}

func TestStitchDeviceCommand(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if (r.URL.Path == "/api/v1/devices" || r.URL.Path == "/devices") && r.Method == http.MethodPost {
			var body struct {
				Name      string `json:"name"`
				PublicKey string `json:"public_key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)

			reg := DeviceRegistration{
				Name:            body.Name,
				PublicKey:       body.PublicKey,
				VirtualIP:       "100.64.128.42",
				AllowedIPs:      []string{"100.64.0.0/10"},
				DNS:             "100.64.0.1",
				ServerPublicKey: "serverPubKey1234567890abcdefghijklmnopq=",
				ServerEndpoint:  "vpn.fabric.io:51820",
				CreatedAt:       time.Now(),
			}
			_ = json.NewEncoder(w).Encode(reg)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("FABRIC_SYS_CONFIG_DIR", tmpDir)
	caFile := filepath.Join(tmpDir, "ca.crt")
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}
	_ = os.WriteFile(caFile, pem.EncodeToMemory(pemBlock), 0644)

	cfg := &Config{
		Host:   ts.URL,
		Token:  "test-token",
		CACert: caFile,
	}
	_ = SaveConfig(cfg)

	outFile := filepath.Join(tmpDir, "pixel7.conf")
	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"stitch", "device", "pixel7", "--out", outFile, "--web=false"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric stitch device failed: %v", err)
	}

	confBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read generated conf file: %v", err)
	}

	confStr := string(confBytes)
	if !strings.Contains(confStr, "[Interface]") || !strings.Contains(confStr, "[Peer]") {
		t.Errorf("conf file missing INI headers:\n%s", confStr)
	}
	if !strings.Contains(confStr, "Address = 100.64.128.42/10") {
		t.Errorf("conf file missing virtual IP address:\n%s", confStr)
	}
	if !strings.Contains(confStr, "DNS = 100.64.0.1") {
		t.Errorf("conf file missing DNS gateway:\n%s", confStr)
	}
	if !strings.Contains(confStr, "Endpoint = vpn.fabric.io:51820") {
		t.Errorf("conf file missing server endpoint:\n%s", confStr)
	}
	if !strings.Contains(confStr, "AllowedIPs = 100.64.0.0/10") {
		t.Errorf("conf file missing AllowedIPs:\n%s", confStr)
	}
}

func TestEphemeralWebPortalZeroCleartextHTTPS(t *testing.T) {
	name := "test-appletv"
	pin := "789123"
	conf := "[Interface]\nPrivateKey = testkey\nAddress = 100.64.128.5/10\n"
	filename := "test-appletv.conf"

	portal, err := StartEphemeralWebPortal(name, pin, conf, filename)
	if err != nil {
		t.Fatalf("StartEphemeralWebPortal failed: %v", err)
	}
	defer portal.Stop()

	// Invariant: Zero-Cleartext Invariant (Must be https://)
	if !strings.HasPrefix(portal.URL, "https://") {
		t.Fatalf("expected https:// URL to satisfy Zero-Cleartext Invariant, got %q", portal.URL)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	// 1. GET Portal HTML
	resp, err := client.Get(portal.URL)
	if err != nil {
		t.Fatalf("failed to GET portal URL: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Fabric Device Pairing") {
		t.Errorf("HTML page missing expected content: %s", string(body))
	}
	if strings.Contains(string(body), `type="hidden" name="pin"`) {
		t.Errorf("HTML page must not leak pre-filled hidden PIN in form: %s", string(body))
	}
	if !strings.Contains(string(body), `name="pin"`) || !strings.Contains(string(body), `type="text"`) {
		t.Errorf("HTML page must render an interactive text input for PIN: %s", string(body))
	}

	// 2. POST with invalid PIN
	postDataInvalid := url.Values{"pin": {"000000"}}
	respInvalid, err := client.PostForm(portal.URL, postDataInvalid)
	if err != nil {
		t.Fatalf("failed to POST invalid PIN: %v", err)
	}
	_ = respInvalid.Body.Close()
	if respInvalid.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for bad PIN, got %d", respInvalid.StatusCode)
	}

	// 3. POST with valid PIN
	postDataValid := url.Values{"pin": {pin}}
	respValid, err := client.PostForm(portal.URL, postDataValid)
	if err != nil {
		t.Fatalf("failed to POST valid PIN: %v", err)
	}
	validBody, _ := io.ReadAll(respValid.Body)
	_ = respValid.Body.Close()
	if respValid.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for valid PIN, got %d", respValid.StatusCode)
	}
	if string(validBody) != conf {
		t.Errorf("expected conf %q, got %q", conf, string(validBody))
	}
	disp := respValid.Header.Get("Content-Disposition")
	if !strings.Contains(disp, filename) {
		t.Errorf("expected Content-Disposition to contain %q, got %q", filename, disp)
	}
}

func TestStitchDeviceWithSubnetFlag(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if (r.URL.Path == "/api/v1/devices" || r.URL.Path == "/devices") && r.Method == http.MethodPost {
			resp := map[string]interface{}{
				"status":           "registered",
				"device_name":      "ipad-pro",
				"virtual_ip":       "10.42.128.5",
				"dns_gateway":      "10.42.0.1",
				"server_public_key": "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890=",
				"server_endpoint":  "vpn.fabric.io:51820",
				"subnet":           "10.42.0.0/16",
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("FABRIC_SYS_CONFIG_DIR", tmpDir)
	caFile := filepath.Join(tmpDir, "ca.crt")
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}
	_ = os.WriteFile(caFile, pem.EncodeToMemory(pemBlock), 0644)

	cfg := &Config{
		Host:   ts.URL,
		Token:  "test-token",
		CACert: caFile,
	}
	_ = SaveConfig(cfg)

	outFile := filepath.Join(tmpDir, "ipad-pro.conf")
	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"stitch", "device", "ipad-pro", "--out", outFile, "--web=false", "--subnet", "10.42.0.0/16"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric stitch device --subnet failed: %v", err)
	}

	confBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read generated conf file: %v", err)
	}

	confStr := string(confBytes)
	if !strings.Contains(confStr, "AllowedIPs = 10.42.0.0/16") {
		t.Errorf("conf file missing custom AllowedIPs 10.42.0.0/16, got:\n%s", confStr)
	}
	if !strings.Contains(confStr, "Address = 10.42.128.5/16") {
		t.Errorf("conf file missing subnet mask /16 in Address, got:\n%s", confStr)
	}
}

func TestDeviceRmCanonicalCommandStrictAliases(t *testing.T) {
	if len(deviceRmCmd.Aliases) != 0 {
		t.Errorf("device rm command must adhere to canonical verb invariant (no non-canonical aliases), got: %+v", deviceRmCmd.Aliases)
	}
}



