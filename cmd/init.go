package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/spf13/cobra"
)

var (
	initForce    bool
	initWithAuth bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize nokey configuration",
	Long: `Create starter config.yaml and policies.yaml in the nokey config directory
with explanatory comments. Existing files are not overwritten unless --force is used.

Use --with-auth to also run PIN setup after generating configuration files.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing configuration files")
	initCmd.Flags().BoolVar(&initWithAuth, "with-auth", false, "Run PIN setup after generating config")
}

// writeIfNotExists writes content to path, creating parent dirs as needed.
// Returns true if the file was written, false if it already existed (and force is false).
var writeInitFile = func(path string, content []byte, force bool) (bool, error) {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, fmt.Errorf("failed to create directory %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		return false, fmt.Errorf("failed to write %s: %w", path, err)
	}
	return true, nil
}

func runInit(cmd *cobra.Command, args []string) error {
	configDir, err := config.ConfigDir()
	if err != nil {
		return fmt.Errorf("failed to determine config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	policiesPath := filepath.Join(configDir, "policies.yaml")

	wrote, err := writeInitFile(configPath, []byte(starterConfig), initForce)
	if err != nil {
		return err
	}
	if wrote {
		fmt.Printf("Created %s\n", configPath)
	} else {
		fmt.Printf("Skipped %s (already exists, use --force to overwrite)\n", configPath)
	}

	wrote, err = writeInitFile(policiesPath, []byte(starterPolicies), initForce)
	if err != nil {
		return err
	}
	if wrote {
		fmt.Printf("Created %s\n", policiesPath)
	} else {
		fmt.Printf("Skipped %s (already exists, use --force to overwrite)\n", policiesPath)
	}

	if initWithAuth {
		fmt.Println("\nSetting up PIN authentication...")
		if err := runAuthSetup(cmd, nil); err != nil {
			return fmt.Errorf("PIN setup failed: %w", err)
		}
	}

	fmt.Printf("\nConfiguration directory: %s\n", configDir)
	fmt.Println("Edit the files above to customize nokey for your workflow.")
	return nil
}

const starterConfig = `# nokey configuration
# See: https://github.com/nokey-ai/nokey

# Keyring backend (leave empty for OS default)
# Options: keychain (macOS), wincred (Windows), secret-service (Linux)
# default_backend: ""

# Redact secret values from subprocess output by default
# redact_by_default: false

# Custom service name for keyring entries
# service_name: nokey

# Authentication settings
auth:
  # Default method: pin, oauth, both, or none (auto-detect if empty)
  # default_method: ""

  # Session TTL — how long a PIN entry remains valid (max 8h)
  # session_ttl: 15m

  # Skip the y/N confirmation prompt in exec
  # skip_confirm: false

# Audit logging
# audit:
#   enabled: false
#   max_entries: 1000
#   retention_days: 90
`

const starterPolicies = `# nokey policies — controls which commands can access which secrets.
#
# Without this file, nokey runs in allow-all mode. Adding rules switches
# to deny-by-default: only matched commands can access matched secrets.

# Global approval mode: "always" or "never"
# approval: always

rules:
  # Allow Claude Code to read AI provider keys
  - commands:
      - "claude"
    secrets:
      - "ANTHROPIC_API_KEY"
      - "OPENAI_API_KEY"

  # Allow the GitHub CLI to use your GitHub token
  - commands:
      - "gh"
    secrets:
      - "GITHUB_TOKEN"
    approval: never

# Proxy rules — inject secrets into HTTP headers via nokey proxy
# proxy:
#   rules:
#     - hosts:
#         - "api.anthropic.com"
#       headers:
#         x-api-key: "$ANTHROPIC_API_KEY"
#     - hosts:
#         - "api.openai.com"
#       headers:
#         Authorization: "Bearer $OPENAI_API_KEY"
`
