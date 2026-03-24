package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nokey-ai/nokey/internal/sensitive"
	"github.com/spf13/cobra"
)

var (
	shellType string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export shell snippet for current session",
	Long: `Export shell snippet to set environment variables for the current session.

This is a "careful mode" feature that exposes secrets to the current shell session.
Use with caution as the secrets will be visible in the shell's memory.

If PIN authentication is configured, you will be prompted to enter your PIN.
All exports are recorded in the audit log (if enabled).

Usage:
  eval "$(nokey export --shell bash)"
  eval "$(nokey export --shell zsh)"
  # PowerShell: Invoke-Expression (nokey export --shell powershell)

Supported shells: bash, zsh, fish, powershell`,
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVar(&shellType, "shell", "", "Shell type (bash, zsh, fish, powershell)")
	_ = exportCmd.MarkFlagRequired("shell")
}

func runExport(cmd *cobra.Command, args []string) error {
	// Get all secrets
	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	// Check if authentication is required
	var secrets map[string]string
	var authMethod string
	if cfg.RequireAuth || store.HasPIN() {
		// Use authenticated access (requires PIN entry)
		secrets, err = store.AuthenticatedGetAll()
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		authMethod = "pin"
	} else {
		// Regular access (no PIN required)
		secrets, err = store.GetAll()
		if err != nil {
			return fmt.Errorf("failed to retrieve secrets: %w", err)
		}
		authMethod = "none"
	}

	defer sensitive.ClearMap(secrets)

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no secrets stored")
		return nil
	}

	// Generate shell-specific export commands
	switch strings.ToLower(shellType) {
	case "bash", "zsh":
		for key, value := range secrets {
			// Escape single quotes in the value
			escapedValue := strings.ReplaceAll(value, "'", "'\\''")
			fmt.Printf("export %s='%s'\n", key, escapedValue)
		}
	case "fish":
		for key, value := range secrets {
			// Escape single quotes: end string, add escaped quote, restart
			escapedValue := strings.ReplaceAll(value, "'", "'\\''")
			fmt.Printf("set -gx %s '%s'\n", key, escapedValue)
		}
	case "powershell", "pwsh":
		for key, value := range secrets {
			// Escape single quotes in the value
			escapedValue := strings.ReplaceAll(value, "'", "''")
			fmt.Printf("$env:%s='%s'\n", key, escapedValue)
		}
	default:
		return fmt.Errorf("unsupported shell type: %s (supported: bash, zsh, fish, powershell)", shellType)
	}

	// Record audit entry
	secretNames := make([]string, 0, len(secrets))
	for name := range secrets {
		secretNames = append(secretNames, name)
	}
	AppFromCmd(cmd).RecordAudit(store, "export", shellType, authMethod, secretNames, true, "")

	return nil
}
