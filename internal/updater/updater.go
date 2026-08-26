package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fabric/internal/service"
	"fabric/internal/version"
)

// Config configures the transactional self-updater engine.
type Config struct {
	CurrentVersion string
	TargetVersion  string
	DownloadURL    string
	ReleaseAPIURL  string
	InstallDir     string
	Force          bool
	CheckOnly      bool
	UpdateAll      bool
	RestartService bool
	OS             string
	Arch           string
	HTTPClient     *http.Client
	Out            io.Writer
}

// ReleaseAsset represents a single downloadable binary asset from a release.
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// ReleaseInfo encapsulates GitHub release metadata.
type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	PublishedAt string         `json:"published_at"`
	Assets      []ReleaseAsset `json:"assets"`
	Prerelease  bool           `json:"prerelease"`
}

// StagedBinary tracks an individual binary being upgraded in the pipeline.
type StagedBinary struct {
	Role            string
	AssetName       string
	DownloadURL     string
	TargetPath      string
	TempStagePath   string
	BackupPath      string
	ExpectedSHA256  string
	ActualSHA256    string
	Committed       bool
}

// Updater is the deep domain module executing staged self-updates with atomic rollbacks.
type Updater struct {
	cfg        Config
	httpClient *http.Client
	out        io.Writer
	osName     string
	archName   string
}

// New creates and initializes a new Updater instance.
func New(cfg Config) *Updater {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	out := cfg.Out
	if out == nil {
		out = os.Stdout
	}
	osName := cfg.OS
	if osName == "" {
		osName = runtime.GOOS
	}
	archName := NormalizeArch(cfg.Arch)
	if archName == "" {
		archName = NormalizeArch(runtime.GOARCH)
	}

	return &Updater{
		cfg:        cfg,
		httpClient: client,
		out:        out,
		osName:     osName,
		archName:   archName,
	}
}

// NormalizeArch translates runtime.GOARCH and system names into standard release asset architecture names.
func NormalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armhf", "arm":
		return "arm"
	default:
		return arch
	}
}

// FetchReleaseInfo queries release metadata from GitHub or custom API endpoint.
func (u *Updater) FetchReleaseInfo(ctx context.Context, targetVersion string) (*ReleaseInfo, error) {
	apiURL := u.cfg.ReleaseAPIURL
	if apiURL == "" {
		if targetVersion == "" || targetVersion == "latest" {
			apiURL = "https://api.github.com/repos/sh7vansh/fabric/releases/latest"
		} else {
			tag := targetVersion
			if !strings.HasPrefix(tag, "v") {
				tag = "v" + tag
			}
			apiURL = fmt.Sprintf("https://api.github.com/repos/sh7vansh/fabric/releases/tags/%s", tag)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "fabric-updater")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query release metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("release %q not found", targetVersion)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release API returned HTTP %s", resp.Status)
	}

	var info ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse release metadata: %w", err)
	}

	return &info, nil
}

// VerifyExecutableViability checks file permissions and executable magic headers prior to installation.
func VerifyExecutableViability(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("target %s is not a regular file", path)
	}
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("file %s is not marked executable (mode: %o)", path, info.Mode().Perm())
	}
	if info.Size() < 4 {
		return fmt.Errorf("file %s is too small to be a valid executable (%d bytes)", path, info.Size())
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file for viability check: %w", err)
	}
	defer f.Close()

	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil || n < 4 {
		return fmt.Errorf("failed to read binary header for viability check: %w", err)
	}

	// 1. ELF magic: 0x7F 'E' 'L' 'F'
	if header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return nil
	}
	// 2. Script hashbang: '#!'
	if header[0] == '#' && header[1] == '!' {
		return nil
	}
	// 3. Mach-O 32/64-bit / Universal binary magics
	if (header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && (header[3] == 0xCE || header[3] == 0xCF)) ||
		(header[0] == 0xCE && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE) {
		return nil
	}
	// 4. Windows PE MZ header
	if header[0] == 'M' && header[1] == 'Z' {
		return nil
	}

	return fmt.Errorf("file %s lacks valid executable magic header", path)
}

// FetchChecksumManifest fetches and parses SHA-256 digests from checksums.txt.
func (u *Updater) FetchChecksumManifest(ctx context.Context, release *ReleaseInfo, latestTag string) (map[string]string, error) {
	manifestMap := make(map[string]string)

	baseURL := u.cfg.DownloadURL
	if baseURL == "" {
		if envDownload := os.Getenv("FABRIC_DOWNLOAD_URL"); envDownload != "" {
			baseURL = strings.TrimRight(envDownload, "/")
		} else {
			baseURL = fmt.Sprintf("https://github.com/sh7vansh/fabric/releases/download/%s", latestTag)
		}
	}

	manifestURL := baseURL + "/checksums.txt"
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return manifestMap, err
	}
	req.Header.Set("User-Agent", "fabric-updater")
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return manifestMap, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				hash := strings.ToLower(fields[0])
				name := strings.TrimPrefix(fields[1], "*")
				name = filepath.Base(name)
				if len(hash) == 64 {
					manifestMap[name] = hash
				}
			}
		}
	}

	return manifestMap, nil
}

// FetchSingleAssetChecksum attempts to fetch <assetName>.sha256 directly.
func (u *Updater) FetchSingleAssetChecksum(ctx context.Context, downloadURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL+".sha256", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "fabric-updater")
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fields := strings.Fields(string(body))
		if len(fields) > 0 && len(fields[0]) == 64 {
			return strings.ToLower(fields[0]), nil
		}
	}

	return "", fmt.Errorf("no checksum manifest found")
}

// ResolveAssetDownloadURL determines the asset download URI.
func (u *Updater) ResolveAssetDownloadURL(release *ReleaseInfo, latestTag, assetName string) string {
	if u.cfg.DownloadURL != "" {
		return fmt.Sprintf("%s/%s", strings.TrimRight(u.cfg.DownloadURL, "/"), assetName)
	}
	if envDownload := os.Getenv("FABRIC_DOWNLOAD_URL"); envDownload != "" {
		return fmt.Sprintf("%s/%s", strings.TrimRight(envDownload, "/"), assetName)
	}
	if release != nil {
		for _, asset := range release.Assets {
			if asset.Name == assetName {
				return asset.BrowserDownloadURL
			}
		}
	}
	return fmt.Sprintf("https://github.com/sh7vansh/fabric/releases/download/%s/%s", latestTag, assetName)
}

func computeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolveChecksum looks up the asset hash from the manifest or probes single asset checksum.
func (u *Updater) resolveChecksum(ctx context.Context, manifest map[string]string, assetName, downloadURL string) string {
	if hash, ok := manifest[assetName]; ok && hash != "" {
		return hash
	}
	if hash, err := u.FetchSingleAssetChecksum(ctx, downloadURL); err == nil && hash != "" {
		return hash
	}
	return ""
}

// Run executes the complete update pipeline: Check -> Fetch -> Verify -> Stage -> Commit -> Rollback.
func (u *Updater) Run(ctx context.Context) error {
	currentVer := u.cfg.CurrentVersion
	if currentVer == "" {
		currentVer = version.Version
	}

	fmt.Fprintf(u.out, "[+] Checking for Fabric updates (current: %s, os: %s, arch: %s)...\n", currentVer, u.osName, u.archName)

	release, err := u.FetchReleaseInfo(ctx, u.cfg.TargetVersion)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	latestTag := release.TagName
	if latestTag == "" {
		latestTag = release.Name
	}

	cmp := version.Compare(currentVer, latestTag)

	if u.cfg.CheckOnly {
		if cmp < 0 {
			fmt.Fprintf(u.out, "\n📢 An update is available: %s -> %s\n", currentVer, latestTag)
			fmt.Fprintf(u.out, "Run 'fabric update' to install the latest version.\n")
		} else {
			fmt.Fprintf(u.out, "\n✨ Fabric is already up to date (version %s).\n", currentVer)
		}
		return nil
	}

	if cmp >= 0 && !u.cfg.Force {
		fmt.Fprintf(u.out, "\n✨ Fabric is already up to date (version %s).\n", currentVer)
		fmt.Fprintf(u.out, "Use --force to re-install this version.\n")
		return nil
	}

	// 1. Discover target install directory
	installDir := u.cfg.InstallDir
	if installDir == "" {
		if execPath, err := os.Executable(); err == nil {
			if resolved, resolveErr := filepath.EvalSymlinks(execPath); resolveErr == nil {
				execPath = resolved
			}
			if !strings.Contains(execPath, "/tmp/") && !strings.Contains(execPath, "go-build") && !strings.HasSuffix(execPath, ".test") {
				installDir = filepath.Dir(execPath)
			}
		}
		if installDir == "" {
			installDir = "/usr/local/bin"
		}
	}

	_ = os.MkdirAll(installDir, 0755)

	// 2. Fetch Checksums Manifest
	checksumManifest, err := u.FetchChecksumManifest(ctx, release, latestTag)
	if err != nil || len(checksumManifest) == 0 {
		// Attempt individual checksum probe later if needed
	}

	// 3. Plan binaries to update
	var plannedBinaries []*StagedBinary

	// Primary CLI binary
	cliAssetName := fmt.Sprintf("fabric-%s-%s", u.osName, u.archName)
	cliDownloadURL := u.ResolveAssetDownloadURL(release, latestTag, cliAssetName)
	cliExpectedHash := u.resolveChecksum(ctx, checksumManifest, cliAssetName, cliDownloadURL)
	if cliExpectedHash == "" {
		return fmt.Errorf("security error: checksum manifest missing for %s", cliAssetName)
	}

	plannedBinaries = append(plannedBinaries, &StagedBinary{
		Role:           "cli",
		AssetName:      cliAssetName,
		DownloadURL:    cliDownloadURL,
		TargetPath:     filepath.Join(installDir, "fabric"),
		ExpectedSHA256: cliExpectedHash,
	})

	// Companion binaries: fabric-server, fabric-thread
	companionRoles := []string{"server", "thread"}
	for _, role := range companionRoles {
		binName := "fabric-" + role
		targetBinPath := filepath.Join(installDir, binName)
		_, statErr := os.Stat(targetBinPath)

		if u.cfg.UpdateAll || statErr == nil {
			compAssetName := fmt.Sprintf("fabric-%s-%s-%s", role, u.osName, u.archName)
			compDownloadURL := u.ResolveAssetDownloadURL(release, latestTag, compAssetName)
			compHash := u.resolveChecksum(ctx, checksumManifest, compAssetName, compDownloadURL)
			if compHash != "" {
				plannedBinaries = append(plannedBinaries, &StagedBinary{
					Role:           role,
					AssetName:      compAssetName,
					DownloadURL:    compDownloadURL,
					TargetPath:     targetBinPath,
					ExpectedSHA256: compHash,
				})
			}
		}
	}

	fmt.Fprintf(u.out, "[+] Updating Fabric: v%s -> %s (%s/%s)...\n", strings.TrimPrefix(currentVer, "v"), latestTag, u.osName, u.archName)

	// 4. Staging Phase: Fetch & Verify each binary in temporary location
	defer func() {
		// Clean up any residual uncommitted temp files
		for _, staged := range plannedBinaries {
			if staged.TempStagePath != "" {
				_ = os.Remove(staged.TempStagePath)
			}
		}
	}()

	for _, b := range plannedBinaries {
		fmt.Fprintf(u.out, "[+] Downloading %s...\n", b.AssetName)
		tempFile, err := os.CreateTemp(filepath.Dir(b.TargetPath), ".fabric-update-*")
		if err != nil {
			tempFile, err = os.CreateTemp(os.TempDir(), ".fabric-update-*")
			if err != nil {
				return fmt.Errorf("failed to create temporary file for %s: %w", b.AssetName, err)
			}
		}
		b.TempStagePath = tempFile.Name()

		req, err := http.NewRequestWithContext(ctx, "GET", b.DownloadURL, nil)
		if err != nil {
			tempFile.Close()
			return err
		}
		req.Header.Set("User-Agent", "fabric-updater")

		resp, err := u.httpClient.Do(req)
		if err != nil {
			tempFile.Close()
			return fmt.Errorf("download failed for %s: %w", b.AssetName, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			tempFile.Close()
			return fmt.Errorf("download %s failed with HTTP %s", b.AssetName, resp.Status)
		}

		if _, err := io.Copy(tempFile, resp.Body); err != nil {
			resp.Body.Close()
			tempFile.Close()
			return fmt.Errorf("failed to write payload for %s: %w", b.AssetName, err)
		}
		resp.Body.Close()
		tempFile.Close()

		// Verify SHA-256
		actualHash, err := computeSHA256(b.TempStagePath)
		if err != nil {
			return fmt.Errorf("failed to compute checksum for %s: %w", b.AssetName, err)
		}
		b.ActualSHA256 = actualHash
		if !strings.EqualFold(actualHash, b.ExpectedSHA256) {
			return fmt.Errorf("security error: SHA256 checksum mismatch for %s (expected %s, got %s)",
				b.AssetName, b.ExpectedSHA256, actualHash)
		}

		if err := os.Chmod(b.TempStagePath, 0755); err != nil {
			return fmt.Errorf("failed to set permissions on %s: %w", b.AssetName, err)
		}

		// Verify executable viability
		if err := VerifyExecutableViability(b.TempStagePath); err != nil {
			return fmt.Errorf("executable viability verification failed for %s: %w", b.AssetName, err)
		}
	}

	// 5. Commit Phase with Atomic Backup & Rollback
	rollbackNeeded := false
	for _, b := range plannedBinaries {
		// Create backup of existing binary if present
		if _, err := os.Stat(b.TargetPath); err == nil {
			b.BackupPath = b.TargetPath + ".old"
			_ = os.Remove(b.BackupPath)
			if err := copyBinary(b.TargetPath, b.BackupPath); err != nil {
				// Non-fatal if backup copy fails, but log
			}
		}

		// Atomic replace
		if err := os.Rename(b.TempStagePath, b.TargetPath); err != nil {
			// Fallback with sudo if permission denied
			sudoCmd := exec.Command("sudo", "install", "-m", "0755", b.TempStagePath, b.TargetPath)
			if sudoErr := sudoCmd.Run(); sudoErr != nil {
				rollbackNeeded = true
				break
			}
		}
		b.Committed = true
		b.TempStagePath = ""
		fmt.Fprintf(u.out, "[+] Installed %s to %s\n", b.AssetName, b.TargetPath)
	}

	if rollbackNeeded {
		fmt.Fprintf(u.out, "[!] Commit failure encountered. Executing automated rollback...\n")
		for _, b := range plannedBinaries {
			if b.Committed && b.BackupPath != "" {
				if _, err := os.Stat(b.BackupPath); err == nil {
					_ = os.Rename(b.BackupPath, b.TargetPath)
				}
			}
		}
		return fmt.Errorf("update failed during binary replacement: changes rolled back")
	}

	// 6. Service Restart Phase (if requested)
	if u.cfg.RestartService {
		mgr := service.NewInitManager()
		for _, role := range []string{"server", "thread"} {
			if err := mgr.HandleAction("restart", role); err == nil {
				fmt.Fprintf(u.out, "[+] Restarted background %s service.\n", role)
			}
		}
	}

	fmt.Fprintf(u.out, "\n[+] Successfully updated Fabric to %s!\n", latestTag)
	return nil
}

func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
