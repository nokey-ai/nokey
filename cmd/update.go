package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/nokey-ai/nokey/internal/update"
	"github.com/nokey-ai/nokey/internal/version"
	"github.com/spf13/cobra"
)

var (
	updateCheck bool
	updateForce bool
)

// Overridable in tests.
var (
	updateClientFn     = update.NewClient
	updateExecutableFn = os.Executable
	updateCurrentFn    = func() string { return version.Version }
	updateBrewFn       = func(ctx context.Context) error {
		c := exec.CommandContext(ctx, "brew", "upgrade", "--cask", "nokey-ai/tap/nokey")
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run()
	}
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update nokey to the latest release",
	Long: `Download the latest nokey release from GitHub, verify it against the
release's checksums.txt, and replace the running binary.

A Homebrew install is upgraded with 'brew upgrade --cask nokey-ai/tap/nokey'
instead, so brew keeps track of the installed version. Development builds
are not replaced unless --force is given.`,
	Args: cobra.NoArgs,
	RunE: runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVar(&updateCheck, "check", false, "Only report whether a newer release exists")
	updateCmd.Flags().BoolVar(&updateForce, "force", false, "Replace a development build, or reinstall the current release")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := updateClientFn()
	rel, err := client.Latest(ctx)
	if err != nil {
		return err
	}
	latest := rel.Version()
	current := updateCurrentFn()

	dev := !update.IsRelease(current)
	newer := true
	if !dev {
		if newer, err = update.Newer(latest, current); err != nil {
			return err
		}
	}

	switch {
	case dev:
		fmt.Printf("nokey %s is a development build; the latest release is %s.\n", current, latest)
	case newer:
		fmt.Printf("nokey %s is available (installed: %s).\n", latest, current)
	default:
		fmt.Printf("nokey %s is the latest release.\n", current)
	}
	if updateCheck {
		return nil
	}
	if !updateForce && (dev || !newer) {
		if dev {
			fmt.Println("Run 'nokey update --force' to replace it with the release build.")
		}
		return nil
	}

	exe, err := updateExecutableFn()
	if err != nil {
		return fmt.Errorf("locate nokey binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	if update.HomebrewManaged(exe) {
		fmt.Println("Installed with Homebrew; running 'brew upgrade --cask nokey-ai/tap/nokey'.")
		if err := updateBrewFn(ctx); err != nil {
			return fmt.Errorf("brew upgrade: %w", err)
		}
		return nil
	}

	fmt.Printf("Downloading nokey %s for %s/%s...\n", latest, runtime.GOOS, runtime.GOARCH)
	bin, err := client.Download(ctx, rel, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	if err := update.Replace(exe, bin, runtime.GOOS); err != nil {
		return fmt.Errorf("%w (if %s is not writable, re-run with sudo)", err, filepath.Dir(exe))
	}
	fmt.Printf("Updated %s to nokey %s.\n", exe, latest)
	return nil
}
