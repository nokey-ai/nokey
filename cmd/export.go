package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nokey-ai/nokey/internal/env"
	"github.com/nokey-ai/nokey/internal/sensitive"
	"github.com/nokey-ai/nokey/internal/session"
	"github.com/spf13/cobra"
)

var (
	shellType    string
	exportOnly   string
	exportExcept string
)

// fishQuoteEscaper escapes a value for use inside fish single quotes.
var fishQuoteEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export shell snippet for current session",
	Long: `Export shell snippet to set environment variables for the current session.

This is a "careful mode" feature that exposes secrets to the current shell session.
Use with caution as the secrets will be visible in the shell's memory.

Authentication follows the configured method (auth.default_method), as for
exec: you may be asked for your PIN and/or need a valid OAuth token.
All exports are recorded in the audit log (if enabled).

Usage:
  eval "$(nokey export --shell bash)"
  eval "$(nokey export --shell zsh)"
  # PowerShell: Invoke-Expression (nokey export --shell powershell)
  eval "$(nokey export --shell bash --only API_KEY,TOKEN)"

Supported shells: bash, zsh, fish, powershell`,
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVar(&shellType, "shell", "", "Shell type (bash, zsh, fish, powershell)")
	exportCmd.Flags().StringVar(&exportOnly, "only", "", "Only export these secrets (comma-separated, e.g., API_KEY,TOKEN)")
	exportCmd.Flags().StringVar(&exportExcept, "except", "", "Exclude these secrets (comma-separated)")
	_ = exportCmd.MarkFlagRequired("shell")
}

func runExport(cmd *cobra.Command, args []string) error {
	// Reject an unsupported shell before touching the keyring or asking
	// for a PIN.
	switch strings.ToLower(shellType) {
	case "bash", "zsh", "fish", "powershell", "pwsh":
	default:
		return fmt.Errorf("unsupported shell type: %s (supported: bash, zsh, fish, powershell)", shellType)
	}

	// Get all secrets
	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	// Apply --only/--except to the names first so that only the selected
	// values are read from the keyring.
	names, err := store.List()
	if err != nil {
		return fmt.Errorf("failed to retrieve secrets: %w", err)
	}
	stored := len(names)
	names, err = env.FilterNames(names, exportOnly, exportExcept)
	if err != nil {
		return err
	}

	// Authenticate exactly as exec does with no --auth-method flag
	authMethod, err := resolveAuthMethod(store, "")
	if err != nil {
		return err
	}
	sessionTTL, err := session.ParseTTL(cfg.Auth.SessionTTL)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	if names == nil {
		// nil would mean "every secret" to getSecretsForMethod
		names = []string{}
	}
	secrets, err := getSecretsForMethod(store, authMethod, sessionTTL, names)
	if err != nil {
		return err
	}

	defer sensitive.ClearMap(secrets)

	if len(secrets) == 0 {
		if stored > 0 {
			fmt.Fprintln(os.Stderr, "Warning: no secrets to export")
		} else {
			fmt.Fprintln(os.Stderr, "Warning: no secrets stored")
		}
		return nil
	}

	// Emit in sorted order so the output is deterministic across runs
	secretNames := make([]string, 0, len(secrets))
	for name := range secrets {
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)

	// Generate shell-specific export commands
	switch strings.ToLower(shellType) {
	case "bash", "zsh":
		for _, key := range secretNames {
			// Escape single quotes in the value
			escapedValue := strings.ReplaceAll(secrets[key], "'", "'\\''")
			fmt.Printf("export %s='%s'\n", key, escapedValue)
		}
	case "fish":
		for _, key := range secretNames {
			// Inside fish single quotes, backslash and quote must be backslash-escaped
			escapedValue := fishQuoteEscaper.Replace(secrets[key])
			fmt.Printf("set -gx %s '%s'\n", key, escapedValue)
		}
	case "powershell", "pwsh":
		for _, key := range secretNames {
			// Escape single quotes in the value
			escapedValue := strings.ReplaceAll(secrets[key], "'", "''")
			fmt.Printf("$env:%s='%s'\n", key, escapedValue)
		}
	default:
		return fmt.Errorf("unsupported shell type: %s (supported: bash, zsh, fish, powershell)", shellType)
	}

	// Record audit entry
	AppFromCmd(cmd).RecordAudit(store, "export", shellType, authMethod, secretNames, true, "")

	return nil
}
