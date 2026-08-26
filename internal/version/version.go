package version

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Build-time variables injected via -ldflags.
var (
	// Version is the semantic release version of Fabric.
	Version = "1.2.3"

	// GitCommit is the Git commit SHA at build time.
	GitCommit = "unknown"

	// BuildDate is the RFC3339 timestamp when the binary was built.
	BuildDate = "unknown"

	// ProtocolVersion is the canonical Fabric WebSocket protocol version.
	ProtocolVersion = "1.0.0"

	// DefaultDomain is the default DNS and federation domain.
	DefaultDomain = "fabric.mesh"
)

// BuildInfo encapsulates comprehensive runtime and build metadata telemetry.
type BuildInfo struct {
	Version         string `json:"version"`
	GitCommit       string `json:"git_commit"`
	BuildDate       string `json:"build_date"`
	GoVersion       string `json:"go_version"`
	ProtocolVersion string `json:"protocol_version"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	Compiler        string `json:"compiler"`
}

// GetBuildInfo returns the structured build and runtime telemetry for this binary.
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:         Version,
		GitCommit:       GitCommit,
		BuildDate:       BuildDate,
		GoVersion:       runtime.Version(),
		ProtocolVersion: ProtocolVersion,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Compiler:        runtime.Compiler,
	}
}

// JSON returns the serialized JSON representation of BuildInfo.
func (b BuildInfo) JSON() ([]byte, error) {
	return json.Marshal(b)
}

// String returns a human-readable multi-line summary of the build info.
func (b BuildInfo) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Version:          %s\n", b.Version))
	sb.WriteString(fmt.Sprintf("Git Commit:       %s\n", b.GitCommit))
	sb.WriteString(fmt.Sprintf("Build Date:       %s\n", b.BuildDate))
	sb.WriteString(fmt.Sprintf("Go Version:       %s\n", b.GoVersion))
	sb.WriteString(fmt.Sprintf("Protocol Version: %s\n", b.ProtocolVersion))
	sb.WriteString(fmt.Sprintf("OS/Arch:          %s/%s\n", b.OS, b.Arch))
	return sb.String()
}

// Semver represents a parsed Semantic Version 2.0 structure.
type Semver struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
}

// String formats the Semver back to standard string notation.
func (s Semver) String() string {
	res := fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
	if s.Prerelease != "" {
		res += "-" + s.Prerelease
	}
	if s.Build != "" {
		res += "+" + s.Build
	}
	return res
}

// ParseSemver parses a string into a Semver struct.
func ParseSemver(v string) (Semver, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return Semver{}, fmt.Errorf("empty version string")
	}

	var sv Semver

	// Extract build metadata (+...)
	if plusIdx := strings.IndexByte(v, '+'); plusIdx != -1 {
		sv.Build = v[plusIdx+1:]
		v = v[:plusIdx]
	}

	// Extract pre-release (-...)
	if dashIdx := strings.IndexByte(v, '-'); dashIdx != -1 {
		sv.Prerelease = v[dashIdx+1:]
		v = v[:dashIdx]
	}

	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return Semver{}, fmt.Errorf("invalid semantic version format: %q", v)
	}

	for i, part := range parts {
		if part == "" {
			return Semver{}, fmt.Errorf("empty version segment in %q", v)
		}
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 {
			return Semver{}, fmt.Errorf("invalid numeric version segment %q in %q", part, v)
		}
		switch i {
		case 0:
			sv.Major = num
		case 1:
			sv.Minor = num
		case 2:
			sv.Patch = num
		}
	}

	return sv, nil
}

// Compare compares two semantic version strings according to SemVer 2.0 precedence rules.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func Compare(v1, v2 string) int {
	s1, err1 := ParseSemver(v1)
	s2, err2 := ParseSemver(v2)

	if err1 != nil && err2 != nil {
		return strings.Compare(v1, v2)
	}
	if err1 != nil {
		return -1
	}
	if err2 != nil {
		return 1
	}

	// 1. Compare Major
	if s1.Major != s2.Major {
		if s1.Major < s2.Major {
			return -1
		}
		return 1
	}

	// 2. Compare Minor
	if s1.Minor != s2.Minor {
		if s1.Minor < s2.Minor {
			return -1
		}
		return 1
	}

	// 3. Compare Patch
	if s1.Patch != s2.Patch {
		if s1.Patch < s2.Patch {
			return -1
		}
		return 1
	}

	// 4. Pre-release comparison
	// When major, minor, and patch are equal, a normal version has higher precedence than a pre-release version.
	if s1.Prerelease == "" && s2.Prerelease != "" {
		return 1
	}
	if s1.Prerelease != "" && s2.Prerelease == "" {
		return -1
	}
	if s1.Prerelease == s2.Prerelease {
		return 0
	}

	// Compare dot-separated pre-release identifiers
	parts1 := strings.Split(s1.Prerelease, ".")
	parts2 := strings.Split(s2.Prerelease, ".")

	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		p1 := parts1[i]
		p2 := parts2[i]

		n1, err1 := strconv.Atoi(p1)
		n2, err2 := strconv.Atoi(p2)

		if err1 == nil && err2 == nil {
			// Both are numeric
			if n1 != n2 {
				if n1 < n2 {
					return -1
				}
				return 1
			}
		} else if err1 == nil && err2 != nil {
			// Numeric identifier has lower precedence than non-numeric
			return -1
		} else if err1 != nil && err2 == nil {
			// Non-numeric identifier has higher precedence than numeric
			return 1
		} else {
			// Both are non-numeric; compare lexical ASCII
			if p1 != p2 {
				if p1 < p2 {
					return -1
				}
				return 1
			}
		}
	}

	// If all checked parts are equal, larger set of pre-release fields has higher precedence
	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// IsProtocolCompatible returns true if the client and server protocol versions are mutually compatible.
func IsProtocolCompatible(clientProto, serverProto string) bool {
	clientProto = strings.TrimSpace(clientProto)
	serverProto = strings.TrimSpace(serverProto)

	if clientProto == "" || serverProto == "" {
		return true // Fallback compatibility for unversioned legacy handshakes
	}

	c, err1 := ParseSemver(clientProto)
	s, err2 := ParseSemver(serverProto)

	if err1 != nil || err2 != nil {
		// If either is unparseable as semver, fallback to exact string match
		return strings.TrimPrefix(clientProto, "v") == strings.TrimPrefix(serverProto, "v")
	}

	// SemVer breaking change rules:
	// For major version >= 1, major versions must match.
	if c.Major >= 1 || s.Major >= 1 {
		return c.Major == s.Major
	}

	// For initial development (0.x.y), minor version changes are breaking.
	return c.Major == s.Major && c.Minor == s.Minor
}
