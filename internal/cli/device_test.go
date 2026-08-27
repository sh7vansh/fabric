package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
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

	// 4. Test `fabric device inspect iphone-13`
	outBuf.Reset()
	rootCmd.SetArgs([]string{"device", "inspect", "iphone-13"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("fabric device inspect failed: %v", err)
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
