package cli

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"fabric/internal/updater"
	"fabric/internal/version"

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
daemons (fabric-server, fabric-thread) installed in the same binary directory.`,
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
		cfg := updater.Config{
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
		u := updater.New(cfg)
		return u.Run(context.Background())
	},
}

func init() {
	updateCmd.Flags().BoolVarP(&updateCheckOnly, "check", "c", false, "Check for available updates without applying")
	updateCmd.Flags().BoolVarP(&updateForce, "force", "f", false, "Force re-install even if already at latest version")
	updateCmd.Flags().StringVarP(&updateTargetVersion, "version", "v", "", "Target release version to install (defaults to latest)")
	updateCmd.Flags().StringVar(&updateInstallDir, "dir", "", "Target binary installation directory (defaults to current binary location)")
	updateCmd.Flags().BoolVarP(&updateAllBinaries, "all", "a", false, "Update companion daemons (fabric-server, fabric-thread) if present")
	updateCmd.Flags().BoolVar(&updateRestartService, "restart", false, "Restart running systemd/supervisor services after update")

	rootCmd.AddCommand(updateCmd)
}

// Backward-compatible type aliases and helpers for cli package consumers.
type UpdaterConfig = updater.Config
type ReleaseInfo = updater.ReleaseInfo
type ReleaseAsset = updater.ReleaseAsset

// SemverCompare compares two semantic version strings using the canonical version module.
func SemverCompare(v1, v2 string) int {
	return version.Compare(v1, v2)
}

// NormalizeArch translates architecture names using the canonical updater module.
func NormalizeArch(arch string) string {
	return updater.NormalizeArch(arch)
}

// RunUpdate delegates update execution to the updater domain module.
func RunUpdate(cfg updater.Config) error {
	u := updater.New(cfg)
	return u.Run(context.Background())
}

// FetchReleaseInfo queries release metadata.
func FetchReleaseInfo(ctx context.Context, client *http.Client, apiURL, targetVersion string) (*ReleaseInfo, error) {
	u := updater.New(updater.Config{
		ReleaseAPIURL: apiURL,
		HTTPClient:    client,
	})
	return u.FetchReleaseInfo(ctx, targetVersion)
}
