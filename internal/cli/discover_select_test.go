package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseSelectionInput(t *testing.T) {
	mockHosts := []DiscoveredHost{
		{IP: "192.168.1.10", Port: 22, CleanBanner: "OpenSSH_8.9 Ubuntu", Latency: 2 * time.Millisecond},
		{IP: "192.168.1.15", Port: 22, CleanBanner: "OpenSSH_9.2 Debian", Latency: 4 * time.Millisecond},
		{IP: "192.168.1.42", Port: 2222, CleanBanner: "Dropbear_2020", Latency: 1 * time.Millisecond},
		{IP: "192.168.1.99", Port: 22, CleanBanner: "OpenSSH_8.4 Raspbian", Latency: 5 * time.Millisecond},
	}

	tests := []struct {
		name        string
		input       string
		defaultUser string
		wantTargets []StitchTarget
		expectErr   bool
	}{
		{
			name:        "Select all",
			input:       "all",
			defaultUser: "",
			wantTargets: []StitchTarget{
				{Host: "192.168.1.10", Port: "22", Banner: "OpenSSH_8.9 Ubuntu"},
				{Host: "192.168.1.15", Port: "22", Banner: "OpenSSH_9.2 Debian"},
				{Host: "192.168.1.42", Port: "2222", Banner: "Dropbear_2020"},
				{Host: "192.168.1.99", Port: "22", Banner: "OpenSSH_8.4 Raspbian"},
			},
		},
		{
			name:        "Comma separated indexes",
			input:       "1, 3",
			defaultUser: "ubuntu",
			wantTargets: []StitchTarget{
				{Host: "192.168.1.10", Port: "22", User: "ubuntu", Banner: "OpenSSH_8.9 Ubuntu"},
				{Host: "192.168.1.42", Port: "2222", User: "ubuntu", Banner: "Dropbear_2020"},
			},
		},
		{
			name:        "Index range 1-3",
			input:       "1-3",
			defaultUser: "",
			wantTargets: []StitchTarget{
				{Host: "192.168.1.10", Port: "22", Banner: "OpenSSH_8.9 Ubuntu"},
				{Host: "192.168.1.15", Port: "22", Banner: "OpenSSH_9.2 Debian"},
				{Host: "192.168.1.42", Port: "2222", Banner: "Dropbear_2020"},
			},
		},
		{
			name:        "Inline user and port overrides",
			input:       "admin@1, 2:2200, root@3:2223",
			defaultUser: "default_user",
			wantTargets: []StitchTarget{
				{Host: "192.168.1.10", Port: "22", User: "admin", Banner: "OpenSSH_8.9 Ubuntu"},
				{Host: "192.168.1.15", Port: "2200", User: "default_user", Banner: "OpenSSH_9.2 Debian"},
				{Host: "192.168.1.42", Port: "2223", User: "root", Banner: "Dropbear_2020"},
			},
		},
		{
			name:        "Direct IP with user override",
			input:       "devops@10.0.0.99:2222",
			defaultUser: "",
			wantTargets: []StitchTarget{
				{Host: "10.0.0.99", Port: "2222", User: "devops"},
			},
		},
		{
			name:        "Quit input",
			input:       "q",
			wantTargets: nil,
		},
		{
			name:      "Out of range index",
			input:     "5",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := ParseSelectionInput(tt.input, mockHosts, tt.defaultUser)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ParseSelectionInput(%q) error = %v, expectErr = %v", tt.input, err, tt.expectErr)
			}
			if tt.expectErr {
				return
			}

			if len(targets) != len(tt.wantTargets) {
				t.Fatalf("ParseSelectionInput(%q) count = %d; want %d", tt.input, len(targets), len(tt.wantTargets))
			}

			for i := range targets {
				if targets[i].Host != tt.wantTargets[i].Host ||
					targets[i].Port != tt.wantTargets[i].Port ||
					targets[i].User != tt.wantTargets[i].User {
					t.Errorf("Target[%d] = %+v; want %+v", i, targets[i], tt.wantTargets[i])
				}
			}
		})
	}
}

func TestFormatDiscoveredOutput(t *testing.T) {
	mockHosts := []DiscoveredHost{
		{IP: "192.168.1.10", Port: 22, CleanBanner: "OpenSSH_8.9 Ubuntu", Latency: 2 * time.Millisecond},
		{IP: "192.168.1.42", Port: 2222, CleanBanner: "Dropbear_2020", Latency: 1 * time.Millisecond},
	}

	var buf bytes.Buffer
	err := FormatDiscoveredOutput(&buf, mockHosts, true, "")
	if err != nil {
		t.Fatalf("FormatDiscoveredOutput quiet failed: %v", err)
	}
	quietOut := buf.String()
	if !strings.Contains(quietOut, "192.168.1.10") || !strings.Contains(quietOut, "192.168.1.42:2222") {
		t.Errorf("Quiet output missing expected hosts: %s", quietOut)
	}

	buf.Reset()
	err = FormatDiscoveredOutput(&buf, mockHosts, false, "json")
	if err != nil {
		t.Fatalf("FormatDiscoveredOutput JSON failed: %v", err)
	}
	jsonOut := buf.String()
	if !strings.Contains(jsonOut, `"clean_banner": "OpenSSH_8.9 Ubuntu"`) {
		t.Errorf("JSON output missing banner: %s", jsonOut)
	}
}
