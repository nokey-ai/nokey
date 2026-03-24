package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/nokey-ai/nokey/internal/env"
	iexec "github.com/nokey-ai/nokey/internal/exec"
	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/oauth"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/nokey-ai/nokey/internal/redact"
	"github.com/nokey-ai/nokey/internal/sensitive"
	"github.com/nokey-ai/nokey/internal/session"
	"github.com/spf13/cobra"
)

// Injectable function vars for testing.
var (
	execRunFn   = iexec.Run
	redactRunFn = redact.Run
	osExitFn    = os.Exit
)

// migrateWarned ensures the keychain migration hint is only printed once per process.
var migrateWarned bool

var (
	enableRedact  bool
	enableIsolate bool
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
  --isolate       Block network egress to hosts without a proxy rule

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
  nokey exec --auth-method both -- command

  # Block egress to hosts without a proxy rule
  nokey exec --isolate -- curl https://api.openai.com/v1/models`,
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
	execCmd.Flags().BoolVar(&enableIsolate, "isolate", false, "Block network egress to hosts without a proxy rule")
}

func runExec(cmd *cobra.Command, args []string) error {
	// Get all secrets
	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w\n\nRun 'nokey status' to check your setup", err)
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

	// Parse session TTL for PIN caching.
	sessionTTL, err := session.ParseTTL(cfg.Auth.SessionTTL)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	switch authMethodConfig {
	case "pin":
		// PIN authentication only — with session caching
		storedHash, hashErr := store.GetPINHash()
		if hashErr != nil {
			return fmt.Errorf("PIN authentication failed: %w", hashErr)
		}
		if session.Valid(storedHash, sessionTTL) {
			allSecrets, err = store.GetAll()
		} else {
			allSecrets, err = store.AuthenticatedGetAll()
			if err == nil {
				_ = session.Create(storedHash)
			}
		}
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
			return fmt.Errorf("failed to retrieve secrets: %w", err)
		}
		authMethodUsed = "oauth"

	case "both":
		// Both PIN and OAuth required
		// First check OAuth
		if err := validateOAuthToken(store); err != nil {
			return fmt.Errorf("OAuth authentication failed: %w", err)
		}
		// Then require PIN — with session caching
		storedHash, hashErr := store.GetPINHash()
		if hashErr != nil {
			return fmt.Errorf("PIN authentication failed: %w", hashErr)
		}
		if session.Valid(storedHash, sessionTTL) {
			allSecrets, err = store.GetAll()
		} else {
			allSecrets, err = store.AuthenticatedGetAll()
			if err == nil {
				_ = session.Create(storedHash)
			}
		}
		if err != nil {
			return fmt.Errorf("PIN authentication failed: %w", err)
		}
		authMethodUsed = "both"

	case "none":
		// No authentication required
		allSecrets, err = store.GetAll()
		if err != nil {
			return fmt.Errorf("failed to retrieve secrets: %w", err)
		}
		authMethodUsed = "none"

	default:
		return fmt.Errorf("invalid auth method '%s' (supported: pin, oauth, both, none)", authMethodConfig)
	}

	defer sensitive.ClearMap(allSecrets)

	// On macOS, hint about keychain migration if PIN auth was used and migration hasn't been done.
	if !migrateWarned && runtime.GOOS == "darwin" && (authMethodUsed == "pin" || authMethodUsed == "both") && !store.IsKeychainMigrated() {
		fmt.Fprintln(os.Stderr, "Tip: Run 'nokey keychain migrate' to eliminate macOS Keychain password prompts.")
		migrateWarned = true
	}

	if len(allSecrets) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no secrets stored")
	}

	// Filter secrets based on --only and --except flags
	secrets, err := env.FilterSecrets(allSecrets, onlySecrets, exceptSecrets)
	if err != nil {
		return err
	}

	// Show confirmation prompt unless --yes flag or skip_confirm config is set
	if !skipConfirm && !cfg.Auth.SkipConfirm {
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

	// Set up egress-filtering proxy if --isolate is enabled.
	var proxyEnv []string
	if enableIsolate {
		env, cleanup, err := setupIsolationProxy(secrets)
		if err != nil {
			return err
		}
		defer cleanup()
		proxyEnv = env
	}

	// Execute the command
	var exitCode int
	var execErr error
	if enableRedact {
		exitCode, execErr = redactRunFn(args[0], args[1:], secrets, proxyEnv...)
	} else {
		exitCode, execErr = execRunFn(args[0], args[1:], secrets, proxyEnv...)
	}

	// Record audit entry
	{
		secretNames := make([]string, 0, len(secrets))
		for name := range secrets {
			secretNames = append(secretNames, name)
		}
		errorMsg := ""
		if execErr != nil {
			errorMsg = execErr.Error()
		}
		AppFromCmd(cmd).RecordAudit(store, "exec", args[0], authMethodUsed, secretNames, execErr == nil && exitCode == 0, errorMsg)
	}

	if execErr != nil {
		return execErr
	}

	// Exit with the same code as the subprocess
	osExitFn(exitCode)
	return nil
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

// setupIsolationProxy starts a local proxy that blocks egress to hosts without
// a matching proxy rule. Returns env vars to inject and a cleanup function.
func setupIsolationProxy(secrets map[string]string) ([]string, func(), error) {
	noop := func() {}

	// Determine config directory.
	configDir, err := getConfigDir()
	if err != nil {
		return nil, noop, fmt.Errorf("failed to get config directory: %w", err)
	}

	// Load policy to get proxy rules.
	pol, err := policy.Load(configDir)
	if err != nil {
		return nil, noop, fmt.Errorf("failed to load policy: %w", err)
	}
	rules := pol.ProxyRules()
	if len(rules) == 0 {
		return nil, noop, fmt.Errorf("--isolate requires at least one proxy rule in %s/policies.yaml", configDir)
	}

	// Load or create the local CA.
	ca, err := proxy.LoadOrCreateCA(configDir)
	if err != nil {
		return nil, noop, fmt.Errorf("failed to load CA: %w", err)
	}

	srv := proxy.NewServer(ca, rules, secrets, pol, nil)
	srv.SetBlockUnmatched(true)

	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		return nil, noop, fmt.Errorf("failed to start isolation proxy: %w", err)
	}

	cleanup := func() {
		_ = srv.Stop(context.Background())
	}

	proxyURL := "http://" + addr
	certFile := configDir + "/ca/ca-cert.pem"

	envVars := []string{
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"SSL_CERT_FILE=" + certFile,
		"NODE_EXTRA_CA_CERTS=" + certFile,
		"REQUESTS_CA_BUNDLE=" + certFile,
	}

	return envVars, cleanup, nil
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
		return fmt.Errorf("no OAuth token found for provider %s (run: nokey auth oauth setup --provider %s --client-id ... --client-secret ...): %w", providerName, providerName, err)
	}

	// Check if token is expired and attempt auto-refresh
	if token.IsExpired() {
		// Check if we have a refresh token
		if token.RefreshToken == "" {
			return fmt.Errorf("OAuth token for %s is expired and no refresh token available (run: nokey auth oauth setup --provider %s --client-id ... --client-secret ...)", providerName, providerName)
		}

		// Load client credentials for refresh
		creds, err := oauth.LoadClientCredentials(store, providerName)
		if err != nil {
			return fmt.Errorf("OAuth token expired but client credentials not found (run: nokey auth oauth setup --provider %s --client-id ... --client-secret ...)", providerName)
		}

		provider := newOAuthProviderFn(providerName, creds, "http://localhost:0/callback")
		ctx := context.Background()

		// Refresh the token
		fmt.Fprintf(os.Stderr, "🔄 Refreshing expired OAuth token for %s...\n", providerName)
		newToken, err := provider.RefreshToken(ctx, token.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to refresh OAuth token (run: nokey auth oauth setup --provider %s --client-id ... --client-secret ...): %w", providerName, err)
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
