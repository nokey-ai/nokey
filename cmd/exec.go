package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/exec"
	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/oauth"
	"github.com/nokey-ai/nokey/internal/redact"
	"github.com/spf13/cobra"
)

var (
	enableRedact  bool
	onlySecrets   string
	exceptSecrets string
	skipConfirm   bool
	authMethod    string
)

var execCmd = &cobra.Command{
	Use:   "exec -- COMMAND [ARGS...]",
	Short: "Execute a command with secrets injected as environment variables",
	Long: `Execute a command with stored secrets injected as environment variables.

By default, you will be prompted to confirm which secrets to inject (security feature).
Use --yes to skip confirmation, or --only/--except to selectively filter secrets.

Security Options:
  --only          Only inject specific secrets (comma-separated)
  --except        Exclude specific secrets (comma-separated)
  --yes           Skip confirmation prompt (use with caution)
  --auth-method   Override authentication method (pin, oauth, both, none)

Examples:
  # Confirm before injecting (default - shows what will be injected)
  nokey exec -- claude "do the thing"

  # Only inject specific secrets (most secure)
  nokey exec --only OPENAI_API_KEY -- claude "do the thing"

  # Inject all except certain secrets
  nokey exec --except DATABASE_URL,AWS_SECRET -- python script.py

  # Skip confirmation (original behavior)
  nokey exec --yes -- cursor .

  # Combine with redaction for extra safety
  nokey exec --only GITHUB_TOKEN --redact -- gh api /user

  # Override auth method (use OAuth instead of PIN)
  nokey exec --auth-method oauth -- command

  # Require both PIN and OAuth (2FA)
  nokey exec --auth-method both -- command`,
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	RunE:                  runExec,
}

func init() {
	rootCmd.AddCommand(execCmd)
	execCmd.Flags().BoolVar(&enableRedact, "redact", false, "Enable output redaction (replaces secret values with [REDACTED:KEY_NAME])")
	execCmd.Flags().StringVar(&onlySecrets, "only", "", "Only inject these secrets (comma-separated, e.g., API_KEY,TOKEN)")
	execCmd.Flags().StringVar(&exceptSecrets, "except", "", "Exclude these secrets (comma-separated)")
	execCmd.Flags().BoolVar(&skipConfirm, "yes", false, "Skip confirmation prompt (inject all secrets without asking)")
	execCmd.Flags().StringVar(&authMethod, "auth-method", "", "Override authentication method (pin, oauth, both, none)")
}

func runExec(cmd *cobra.Command, args []string) error {
	// Get all secrets
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Determine which authentication method to use
	var allSecrets map[string]string
	var authMethodUsed string

	// Get auth method: flag takes precedence over config
	authMethodConfig := authMethod // from flag
	if authMethodConfig == "" {
		// Use config default
		authMethodConfig = cfg.Auth.DefaultMethod
	}
	if authMethodConfig == "" {
		// Legacy behavior: use PIN if configured, otherwise none
		if cfg.RequireAuth || store.HasPIN() {
			authMethodConfig = "pin"
		} else {
			authMethodConfig = "none"
		}
	}

	switch authMethodConfig {
	case "pin":
		// PIN authentication only
		allSecrets, err = store.AuthenticatedGetAll()
		if err != nil {
			return fmt.Errorf("PIN authentication failed: %w", err)
		}
		authMethodUsed = "pin"

	case "oauth":
		// OAuth authentication only
		if err := validateOAuthToken(store); err != nil {
			return fmt.Errorf("OAuth authentication failed: %w", err)
		}
		allSecrets, err = store.GetAll()
		if err != nil {
			return err
		}
		authMethodUsed = "oauth"

	case "both":
		// Both PIN and OAuth required
		// First check OAuth
		if err := validateOAuthToken(store); err != nil {
			return fmt.Errorf("OAuth authentication failed: %w", err)
		}
		// Then require PIN
		allSecrets, err = store.AuthenticatedGetAll()
		if err != nil {
			return fmt.Errorf("PIN authentication failed: %w", err)
		}
		authMethodUsed = "both"

	case "none":
		// No authentication required
		allSecrets, err = store.GetAll()
		if err != nil {
			return err
		}
		authMethodUsed = "none"

	default:
		return fmt.Errorf("invalid auth method '%s' (supported: pin, oauth, both, none)", authMethodConfig)
	}

	if len(allSecrets) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no secrets stored")
	}

	// Filter secrets based on --only and --except flags
	secrets, err := filterSecrets(allSecrets, onlySecrets, exceptSecrets)
	if err != nil {
		return err
	}

	// Show confirmation prompt unless --yes is used
	if !skipConfirm {
		confirmed, err := confirmSecrets(secrets, args[0])
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("aborted")
		}
	}

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no secrets will be injected")
	}

	// Override with config default if flag not explicitly set
	if !cmd.Flags().Changed("redact") {
		enableRedact = cfg.RedactByDefault
	}

	// Execute the command
	var exitCode int
	var execErr error
	if enableRedact {
		exitCode, execErr = redact.Run(args[0], args[1:], secrets)
	} else {
		exitCode, execErr = exec.Run(args[0], args[1:], secrets)
	}

	// Record audit entry if audit logging is enabled
	if cfg.Audit.Enabled {
		secretNames := make([]string, 0, len(secrets))
		for name := range secrets {
			secretNames = append(secretNames, name)
		}

		errorMsg := ""
		if execErr != nil {
			errorMsg = execErr.Error()
		}

		entry := audit.NewAuditEntry(
			"exec",
			args[0],
			authMethodUsed,
			secretNames,
			execErr == nil && exitCode == 0,
			errorMsg,
		)

		// Record audit entry (ignore errors to not disrupt execution)
		if auditErr := audit.Record(store, entry); auditErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to record audit entry: %v\n", auditErr)
		}
	}

	if execErr != nil {
		return execErr
	}

	// Exit with the same code as the subprocess
	os.Exit(exitCode)
	return nil
}

// filterSecrets filters the secrets map based on --only and --except flags
func filterSecrets(allSecrets map[string]string, only, except string) (map[string]string, error) {
	// If both --only and --except are specified, that's an error
	if only != "" && except != "" {
		return nil, fmt.Errorf("cannot use both --only and --except flags")
	}

	// If --only is specified, return only those secrets
	if only != "" {
		onlyList := parseCommaSeparated(only)
		filtered := make(map[string]string)
		for _, key := range onlyList {
			if value, ok := allSecrets[key]; ok {
				filtered[key] = value
			} else {
				return nil, fmt.Errorf("secret not found: %s", key)
			}
		}
		return filtered, nil
	}

	// If --except is specified, return all except those
	if except != "" {
		exceptList := parseCommaSeparated(except)
		exceptMap := make(map[string]bool)
		for _, key := range exceptList {
			exceptMap[key] = true
		}

		filtered := make(map[string]string)
		for key, value := range allSecrets {
			if !exceptMap[key] {
				filtered[key] = value
			}
		}
		return filtered, nil
	}

	// No filtering, return all secrets
	return allSecrets, nil
}

// parseCommaSeparated parses a comma-separated string into a slice of trimmed strings
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// confirmSecrets shows a confirmation prompt asking the user to approve secret injection
func confirmSecrets(secrets map[string]string, command string) (bool, error) {
	if len(secrets) == 0 {
		return true, nil
	}

	// Get sorted list of secret names
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)

	// Show what will be injected
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Command '%s' will have access to %d secret(s):\n", command, len(secrets))
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "  • %s\n", name)
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "⚠️  The subprocess will be able to read these secrets from its environment.\n")
	fmt.Fprintf(os.Stderr, "   Only proceed if you trust this command.\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Continue? [y/N]: ")

	// Read response
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read confirmation: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes", nil
}

// validateOAuthToken validates that a valid OAuth token exists for the configured provider
// Automatically refreshes expired tokens if refresh token is available
func validateOAuthToken(store *keyring.Store) error {
	// Determine which provider is configured by checking which one is enabled
	var providerName string

	if cfg.Auth.OAuth.GitHub.Enabled {
		providerName = "github"
	} else if cfg.Auth.OAuth.Custom.Enabled {
		providerName = "generic"
	} else {
		// Try GitHub by default if no provider explicitly enabled
		providerName = "github"
	}

	// Load the token
	token, err := oauth.LoadToken(store, providerName)
	if err != nil {
		return fmt.Errorf("no OAuth token found for provider %s: %w\nRun: nokey auth oauth setup --provider %s --client-id ... --client-secret ...", providerName, err, providerName)
	}

	// Check if token is expired and attempt auto-refresh
	if token.IsExpired() {
		// Check if we have a refresh token
		if token.RefreshToken == "" {
			return fmt.Errorf("OAuth token for %s is expired and no refresh token available\nRun: nokey auth oauth setup --provider %s --client-id ... --client-secret ...", providerName, providerName)
		}

		// Load client credentials for refresh
		creds, err := oauth.LoadClientCredentials(store, providerName)
		if err != nil {
			return fmt.Errorf("OAuth token expired but client credentials not found\nRun: nokey auth oauth setup --provider %s --client-id ... --client-secret ...", providerName)
		}

		// Create provider based on stored credentials
		var provider oauth.Provider
		ctx := context.Background()

		switch providerName {
		case "github":
			provider = oauth.NewGitHubProvider(creds.ClientID, creds.ClientSecret, "http://localhost:0/callback")

		case "generic":
			provider = oauth.NewGenericProvider(
				"generic",
				creds.AuthURL,
				creds.TokenURL,
				creds.UserInfoURL,
				creds.ClientID,
				creds.ClientSecret,
				creds.Scopes,
				"http://localhost:0/callback",
			)

		default:
			return fmt.Errorf("unsupported OAuth provider: %s", providerName)
		}

		// Refresh the token
		fmt.Fprintf(os.Stderr, "🔄 Refreshing expired OAuth token for %s...\n", providerName)
		newToken, err := provider.RefreshToken(ctx, token.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to refresh OAuth token: %w\nRun: nokey auth oauth setup --provider %s --client-id ... --client-secret ...", err, providerName)
		}

		// Validate the new token
		if err := provider.ValidateToken(ctx, newToken); err != nil {
			return fmt.Errorf("refreshed OAuth token validation failed: %w", err)
		}

		// Save the refreshed token
		if err := oauth.SaveToken(store, providerName, newToken); err != nil {
			return fmt.Errorf("failed to save refreshed OAuth token: %w", err)
		}

		fmt.Fprintf(os.Stderr, "✅ OAuth token refreshed successfully\n")
	}

	// Token is valid
	return nil
}
