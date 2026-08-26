package version_test

import (
	"encoding/json"
	"runtime"
	"testing"

	"fabric/internal/version"
)

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input       string
		wantErr     bool
		wantMajor   int
		wantMinor   int
		wantPatch   int
		wantPre     string
		wantBuild   string
	}{
		{"2.4.1", false, 2, 4, 1, "", ""},
		{"v2.4.1", false, 2, 4, 1, "", ""},
		{"v1.0.0-alpha", false, 1, 0, 0, "alpha", ""},
		{"v1.0.0-alpha.1", false, 1, 0, 0, "alpha.1", ""},
		{"v1.0.0-0.3.7", false, 1, 0, 0, "0.3.7", ""},
		{"v1.0.0-x.7.z.92", false, 1, 0, 0, "x.7.z.92", ""},
		{"v1.0.0-x-y-z.--", false, 1, 0, 0, "x-y-z.--", ""},
		{"1.0.0-alpha+001", false, 1, 0, 0, "alpha", "001"},
		{"1.0.0+20130313144700", false, 1, 0, 0, "", "20130313144700"},
		{"v1.0.0-beta+exp.sha.5114f85", false, 1, 0, 0, "beta", "exp.sha.5114f85"},
		{"v2.0", false, 2, 0, 0, "", ""},
		{"3", false, 3, 0, 0, "", ""},
		{"invalid..version", true, 0, 0, 0, "", ""},
	}

	for _, tt := range tests {
		sv, err := version.ParseSemver(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSemver(%q) err = %v, wantErr = %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if sv.Major != tt.wantMajor || sv.Minor != tt.wantMinor || sv.Patch != tt.wantPatch ||
				sv.Prerelease != tt.wantPre || sv.Build != tt.wantBuild {
				t.Errorf("ParseSemver(%q) = %+v, want major=%d, minor=%d, patch=%d, pre=%q, build=%q",
					tt.input, sv, tt.wantMajor, tt.wantMinor, tt.wantPatch, tt.wantPre, tt.wantBuild)
			}
		}
	}
}

func TestSemverCompare(t *testing.T) {
	orderedList := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.1.0",
		"2.0.0-alpha",
		"2.0.0",
		"2.1.0",
		"2.4.1",
		"3.0.0",
	}

	for i := 0; i < len(orderedList); i++ {
		for j := 0; j < len(orderedList); j++ {
			v1 := orderedList[i]
			v2 := orderedList[j]
			cmp := version.Compare(v1, v2)

			var expected int
			if i < j {
				expected = -1
			} else if i > j {
				expected = 1
			} else {
				expected = 0
			}

			if cmp != expected {
				t.Errorf("Compare(%q, %q) = %d, want %d", v1, v2, cmp, expected)
			}
		}
	}
}

func TestSemverCompare_Equivalence(t *testing.T) {
	equivalences := [][2]string{
		{"v2.4.1", "2.4.1"},
		{"v1.0.0", "1.0.0"},
		{"1.0.0+build1", "1.0.0+build2"},
		{"v2.0.0-rc1+001", "2.0.0-rc1+002"},
	}

	for _, eq := range equivalences {
		cmp := version.Compare(eq[0], eq[1])
		if cmp != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", eq[0], eq[1], cmp)
		}
	}
}

func TestProtocolCompatibility(t *testing.T) {
	tests := []struct {
		client   string
		server   string
		expected bool
	}{
		{"1.0.0", "1.0.0", true},
		{"1.0.0", "1.2.0", true},
		{"1.5.0", "1.0.0", true},
		{"v1.0.0", "1.0.0", true},
		{"", "1.0.0", true}, // Empty fallback assumed compatible with default
		{"1.0.0", "", true},
		{"2.0.0", "1.0.0", false}, // Major mismatch
		{"1.0.0", "2.0.0", false},
		{"0.1.0", "0.2.0", false}, // In 0.x.y, different minor is incompatible
		{"0.1.0", "0.1.5", true},
	}

	for _, tt := range tests {
		got := version.IsProtocolCompatible(tt.client, tt.server)
		if got != tt.expected {
			t.Errorf("IsProtocolCompatible(%q, %q) = %v, want %v", tt.client, tt.server, got, tt.expected)
		}
	}
}

func TestGetBuildInfo(t *testing.T) {
	info := version.GetBuildInfo()
	if info.Version != version.Version {
		t.Errorf("expected version %q, got %q", version.Version, info.Version)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("expected go version %q, got %q", runtime.Version(), info.GoVersion)
	}
	if info.OS != runtime.GOOS {
		t.Errorf("expected OS %q, got %q", runtime.GOOS, info.OS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("expected Arch %q, got %q", runtime.GOARCH, info.Arch)
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal BuildInfo: %v", err)
	}

	var parsed version.BuildInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal BuildInfo JSON: %v", err)
	}

	if parsed.Version != info.Version {
		t.Errorf("parsed version mismatch: %q vs %q", parsed.Version, info.Version)
	}
}
