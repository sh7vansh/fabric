package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fabric/internal/service"

	"github.com/spf13/cobra"
)

var (
	updateCheckOnly      bool
	updateForce          bool
	updateTargetVersion  string
	updateInstallDir     string
	updateAllBinaries    bool
	updateRestartService bool
)

var updateCmd = &cobra.Command{
	Use:     "update [flags]",
	Short:   "Update Fabric binaries to the latest or specified release version",
	GroupID: "system",
	Long: `Download and install the latest or specified release of Fabric.

Performs atomic self-update on the local binary and optionally upgrades companion
daemons (fabric-socket, fabric-node) installed in the same binary directory.`,
	Example: `  # Check if a newer version of Fabric is available
  fabric update --check

  # Update Fabric to the latest release
  fabric update

  # Force re-download and re-install of the current version
  fabric update --force

  # Update to a specific release tag
  fabric update --version v2.2.0

  # Update all binaries in /usr/local/bin and restart active services
  fabric update --all --restart`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := UpdaterConfig{
			CurrentVersion: Version,
			TargetVersion:  updateTargetVersion,
			InstallDir:     updateInstallDir,
			Force:          updateForce,
			CheckOnly:      updateCheckOnly,
			UpdateAll:      updateAllBinaries,
			RestartService: updateRestartService,
			OS:             runtime.GOOS,
			Arch:           runtime.GOARCH,
			HTTPClient:     &http.Client{Timeout: 60 * time.Second},
			Out:            cmd.OutOrStdout(),
		}
		return RunUpdate(cfg)
	},
}

func init() {
	updateCmd.Flags().BoolVarP(&updateCheckOnly, "check", "c", false, "Check for available updates without applying")
	updateCmd.Flags().BoolVarP(&updateForce, "force", "f", false, "Force re-install even if already at latest version")
	updateCmd.Flags().StringVarP(&updateTargetVersion, "version", "v", "", "Target release version to install (defaults to latest)")
	updateCmd.Flags().StringVar(&updateInstallDir, "dir", "", "Target binary installation directory (defaults to current binary location)")
	updateCmd.Flags().BoolVarP(&updateAllBinaries, "all", "a", false, "Update companion daemons (fabric-socket, fabric-node) if present")
	updateCmd.Flags().BoolVar(&updateRestartService, "restart", false, "Restart running systemd/supervisor services after update")

	rootCmd.AddCommand(updateCmd)
}

// UpdaterConfig holds configuration parameters for the update operation.
type UpdaterConfig struct {
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

// SemverCompare compares two semantic version strings (e.g., "v2.1.0" and "2.2.0").
// Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
func SemverCompare(v1, v2 string) int {
	clean1 := strings.TrimPrefix(strings.TrimSpace(v1), "v")
	clean2 := strings.TrimPrefix(strings.TrimSpace(v2), "v")

	parts1 := strings.Split(clean1, ".")
	parts2 := strings.Split(clean2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			// strip prerelease suffixes if any (e.g. 2.1.0-rc1)
			sub := strings.Split(parts1[i], "-")[0]
			n1, _ = strconv.Atoi(sub)
		}
		if i < len(parts2) {
			sub := strings.Split(parts2[i], "-")[0]
			n2, _ = strconv.Atoi(sub)
		}

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return 0
}

// NormalizeArch translates runtime.GOARCH into release asset arch names.
func NormalizeArch(arch string) string {
	switch arch {
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

// FetchReleaseInfo fetches release metadata from GitHub or custom API endpoint.
func FetchReleaseInfo(ctx context.Context, client *http.Client, apiURL, targetVersion string) (*ReleaseInfo, error) {
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

	resp, err := client.Do(req)
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

// FindInstallPath discovers the active binary path or fallback destination.
func FindInstallPath(customDir string) (string, error) {
	if customDir != "" {
		return filepath.Join(customDir, "fabric"), nil
	}

	execPath, err := os.Executable()
	if err == nil {
		if resolved, resolveErr := filepath.EvalSymlinks(execPath); resolveErr == nil {
			execPath = resolved
		}
		// If running from /tmp, test directory, or go-build, fallback to standard locations
		if !strings.Contains(execPath, "/tmp/") && !strings.Contains(execPath, "go-build") && !strings.HasSuffix(execPath, ".test") {
			return execPath, nil
		}
	}

	// Default fallback search
	for _, candidate := range []string{"/usr/local/bin/fabric", filepath.Join(os.Getenv("HOME"), ".local/bin/fabric")} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "/usr/local/bin/fabric", nil
}

// DownloadAndInstallBinary downloads a binary stream and atomically replaces targetPath.
func DownloadAndInstallBinary(ctx context.Context, client *http.Client, downloadURL, targetPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "fabric-updater")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with HTTP %s", resp.Status)
	}

	targetDir := filepath.Dir(targetPath)
	_ = os.MkdirAll(targetDir, 0755)

	// Write to temporary file in target dir (or os.TempDir())
	tmpFile, err := os.CreateTemp(targetDir, ".fabric-update-*")
	if err != nil {
		// Fallback to system temp directory if target directory is not directly writable
		tmpFile, err = os.CreateTemp(os.TempDir(), ".fabric-update-*")
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %w", err)
		}
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write download payload: %w", err)
	}
	_ = tmpFile.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Attempt atomic rename
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// If permission denied, attempt sudo installation
		sudoCmd := exec.Command("sudo", "install", "-m", "0755", tmpPath, targetPath)
		if sudoErr := sudoCmd.Run(); sudoErr != nil {
			return fmt.Errorf("permission denied installing to %s: %w (try running 'sudo fabric update')", targetPath, err)
		}
	}

	return nil
}

// RunUpdate performs the full Fabric update lifecycle based on UpdaterConfig.
func RunUpdate(cfg UpdaterConfig) error {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.OS == "" {
		cfg.OS = runtime.GOOS
	}
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}
	if cfg.CurrentVersion == "" {
		cfg.CurrentVersion = Version
	}

	normArch := NormalizeArch(cfg.Arch)
	ctx := context.Background()

	apiURL := cfg.ReleaseAPIURL
	if apiURL == "" {
		if envAPI := os.Getenv("FABRIC_UPDATE_URL"); envAPI != "" {
			apiURL = envAPI
		} else if envRel := os.Getenv("FABRIC_RELEASE_URL"); envRel != "" {
			apiURL = envRel
		}
	}

	fmt.Fprintf(cfg.Out, "[+] Checking for Fabric updates (current: v%s)...\n", strings.TrimPrefix(cfg.CurrentVersion, "v"))

	release, err := FetchReleaseInfo(ctx, cfg.HTTPClient, apiURL, cfg.TargetVersion)
	if err != nil {
		return fmt.Errorf("update check failed: %w", err)
	}

	latestTag := release.TagName
	cmp := SemverCompare(cfg.CurrentVersion, latestTag)

	if cmp >= 0 && !cfg.Force && cfg.TargetVersion == "" {
		fmt.Fprintf(cfg.Out, "[+] Fabric is already up to date (version %s).\n", latestTag)
		return nil
	}

	if cfg.CheckOnly {
		if cmp < 0 {
			fmt.Fprintf(cfg.Out, "[+] An update is available: v%s -> %s\n    Run 'fabric update' to install the latest release.\n", strings.TrimPrefix(cfg.CurrentVersion, "v"), latestTag)
		} else {
			fmt.Fprintf(cfg.Out, "[+] Fabric is up to date (version %s).\n", latestTag)
		}
		return nil
	}

	installPath, err := FindInstallPath(cfg.InstallDir)
	if err != nil {
		return err
	}
	binDir := filepath.Dir(installPath)

	fmt.Fprintf(cfg.Out, "[+] Updating Fabric: v%s -> %s (linux/%s)...\n", strings.TrimPrefix(cfg.CurrentVersion, "v"), latestTag, normArch)

	// Resolve download URL for CLI binary: fabric-linux-<arch>
	assetName := fmt.Sprintf("fabric-%s-%s", cfg.OS, normArch)
	downloadURL := ""

	if cfg.DownloadURL != "" {
		downloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(cfg.DownloadURL, "/"), assetName)
	} else if envDownload := os.Getenv("FABRIC_DOWNLOAD_URL"); envDownload != "" {
		downloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(envDownload, "/"), assetName)
	} else {
		for _, asset := range release.Assets {
			if asset.Name == assetName {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		if downloadURL == "" {
			// Standard fallback GitHub release asset URL
			downloadURL = fmt.Sprintf("https://github.com/sh7vansh/fabric/releases/download/%s/%s", latestTag, assetName)
		}
	}

	fmt.Fprintf(cfg.Out, "[+] Downloading %s...\n", assetName)
	if err := DownloadAndInstallBinary(ctx, cfg.HTTPClient, downloadURL, installPath); err != nil {
		return fmt.Errorf("failed to update %s: %w", installPath, err)
	}
	fmt.Fprintf(cfg.Out, "[+] Installed %s to %s\n", assetName, installPath)

	// Update companion binaries if requested or if already present in the target directory
	companionRoles := []string{"socket", "node"}
	for _, role := range companionRoles {
		binName := "fabric-" + role
		targetBinPath := filepath.Join(binDir, binName)
		_, statErr := os.Stat(targetBinPath)

		if cfg.UpdateAll || statErr == nil {
			compAssetName := fmt.Sprintf("fabric-%s-%s-%s", role, cfg.OS, normArch)
			compDownloadURL := ""

			if cfg.DownloadURL != "" {
				compDownloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(cfg.DownloadURL, "/"), compAssetName)
			} else if envDownload := os.Getenv("FABRIC_DOWNLOAD_URL"); envDownload != "" {
				compDownloadURL = fmt.Sprintf("%s/%s", strings.TrimRight(envDownload, "/"), compAssetName)
			} else {
				for _, asset := range release.Assets {
					if asset.Name == compAssetName {
						compDownloadURL = asset.BrowserDownloadURL
						break
					}
				}
				if compDownloadURL == "" {
					compDownloadURL = fmt.Sprintf("https://github.com/sh7vansh/fabric/releases/download/%s/%s", latestTag, compAssetName)
				}
			}

			fmt.Fprintf(cfg.Out, "[+] Updating companion binary %s...\n", compAssetName)
			if err := DownloadAndInstallBinary(ctx, cfg.HTTPClient, compDownloadURL, targetBinPath); err != nil {
				fmt.Fprintf(cfg.Out, "[!] Warning: Failed to update %s: %v\n", binName, err)
			} else {
				fmt.Fprintf(cfg.Out, "[+] Installed %s to %s\n", compAssetName, targetBinPath)
			}
		}
	}

	// Restart active services if requested
	if cfg.RestartService {
		mgr := service.NewInitManager()
		for _, role := range []string{"socket", "node"} {
			if err := mgr.HandleAction("restart", role); err == nil {
				fmt.Fprintf(cfg.Out, "[+] Restarted background %s service.\n", role)
			}
		}
	}

	fmt.Fprintf(cfg.Out, "\n[+] Successfully updated Fabric to %s!\n", latestTag)
	return nil
}
