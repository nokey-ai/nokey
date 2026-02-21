package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nokey-ai/nokey/internal/auth"
	"github.com/nokey-ai/nokey/internal/oauth"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication (PIN setup/change/disable)",
	Long: `Manage PIN-based authentication for zero-trust secret access.

When authentication is enabled, you must enter your PIN every time
you access secrets. This prevents AI assistants or automated tools
from accessing your secrets without your explicit approval.

Subcommands:
  setup    - Create a new PIN
  change   - Change your existing PIN
  disable  - Remove PIN requirement
  status   - Check if PIN is configured`,
}

var authSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up PIN-based authentication",
	Long: `Create a PIN that must be entered before accessing secrets.

This enables zero-trust security: even if an AI assistant runs
'nokey exec', it cannot access secrets without you entering the PIN.

The PIN is hashed and stored securely in your OS keyring.`,
	RunE: runAuthSetup,
}

var authChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change your existing PIN",
	Long:  `Change your PIN by entering the old PIN followed by a new one.`,
	RunE:  runAuthChange,
}

var authDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable PIN authentication",
	Long: `Remove the PIN requirement and return to the previous security model.

You will need to enter your current PIN to confirm.`,
	RunE: runAuthDisable,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check authentication status",
	Long:  `Check if PIN authentication is currently configured.`,
	RunE:  runAuthStatus,
}

// OAuth command and subcommands
var (
	oauthProvider     string
	oauthClientID     string
	oauthClientSecret string
	oauthAuthURL      string
	oauthTokenURL     string
	oauthUserInfoURL  string
	oauthScopes       []string
)

var authOAuthCmd = &cobra.Command{
	Use:   "oauth",
	Short: "Manage OAuth authentication",
	Long: `Manage OAuth 2.0 authentication for secret access.

OAuth provides an alternative to PIN-based authentication by using
tokens from OAuth providers like GitHub.

Subcommands:
  setup    - Set up OAuth with a provider
  status   - Check OAuth token status
  refresh  - Manually refresh OAuth token
  logout   - Remove OAuth token`,
}

var authOAuthSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up OAuth authentication with a provider",
	Long: `Configure OAuth authentication with a supported provider.

Supported providers:
  - github: GitHub OAuth (requires GitHub OAuth App)
  - generic: Custom OAuth 2.0 provider

Examples:
  # Set up GitHub OAuth
  nokey auth oauth setup --provider github \
    --client-id YOUR_CLIENT_ID \
    --client-secret YOUR_CLIENT_SECRET

  # Set up custom OAuth provider
  nokey auth oauth setup --provider custom \
    --auth-url https://provider.com/oauth/authorize \
    --token-url https://provider.com/oauth/token \
    --userinfo-url https://provider.com/oauth/userinfo \
    --client-id YOUR_CLIENT_ID \
    --client-secret YOUR_CLIENT_SECRET \
    --scopes openid,profile,email`,
	RunE: runAuthOAuthSetup,
}

var authOAuthStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check OAuth token status",
	Long:  `Display the status of OAuth authentication tokens for all configured providers.`,
	RunE:  runAuthOAuthStatus,
}

var authOAuthRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Manually refresh OAuth token",
	Long:  `Force a refresh of the OAuth access token using the refresh token.`,
	RunE:  runAuthOAuthRefresh,
}

var authOAuthLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove OAuth token",
	Long:  `Remove the stored OAuth token for the specified provider.`,
	RunE:  runAuthOAuthLogout,
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(authSetupCmd)
	authCmd.AddCommand(authChangeCmd)
	authCmd.AddCommand(authDisableCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authOAuthCmd)

	// OAuth subcommands
	authOAuthCmd.AddCommand(authOAuthSetupCmd)
	authOAuthCmd.AddCommand(authOAuthStatusCmd)
	authOAuthCmd.AddCommand(authOAuthRefreshCmd)
	authOAuthCmd.AddCommand(authOAuthLogoutCmd)

	// OAuth setup flags
	authOAuthSetupCmd.Flags().StringVar(&oauthProvider, "provider", "", "OAuth provider (github, generic)")
	authOAuthSetupCmd.Flags().StringVar(&oauthClientID, "client-id", "", "OAuth client ID")
	authOAuthSetupCmd.Flags().StringVar(&oauthClientSecret, "client-secret", "", "OAuth client secret")
	authOAuthSetupCmd.Flags().StringVar(&oauthAuthURL, "auth-url", "", "OAuth authorization URL (for generic provider)")
	authOAuthSetupCmd.Flags().StringVar(&oauthTokenURL, "token-url", "", "OAuth token URL (for generic provider)")
	authOAuthSetupCmd.Flags().StringVar(&oauthUserInfoURL, "userinfo-url", "", "OAuth user info URL (for generic provider)")
	authOAuthSetupCmd.Flags().StringSliceVar(&oauthScopes, "scopes", nil, "OAuth scopes (for generic provider)")
	authOAuthSetupCmd.MarkFlagRequired("provider")
	authOAuthSetupCmd.MarkFlagRequired("client-id")
	authOAuthSetupCmd.MarkFlagRequired("client-secret")

	// OAuth refresh/logout flags
	authOAuthRefreshCmd.Flags().StringVar(&oauthProvider, "provider", "github", "OAuth provider name")
	authOAuthLogoutCmd.Flags().StringVar(&oauthProvider, "provider", "github", "OAuth provider name")
}

func runAuthSetup(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Check if PIN already exists
	if store.HasPIN() {
		return fmt.Errorf("PIN already configured\nUse 'nokey auth change' to change it or 'nokey auth disable' to remove it")
	}

	// Set up new PIN
	hash, err := auth.SetupPIN()
	if err != nil {
		return err
	}

	// Store the hash
	if err := store.SetPINHash(hash); err != nil {
		return err
	}

	fmt.Println("✅ PIN authentication enabled")
	fmt.Println("\nTo use PIN authentication with exec:")
	fmt.Println("  nokey exec -- command")
	fmt.Println("\nOr enable it by default in ~/.config/nokey/config.yaml:")
	fmt.Println("  require_auth: true")

	return nil
}

func runAuthChange(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Get old PIN hash
	oldHash, err := store.GetPINHash()
	if err != nil {
		return err
	}

	// Change PIN (verifies old PIN first)
	newHash, err := auth.ChangePIN(oldHash)
	if err != nil {
		return err
	}

	// Store new hash
	if err := store.SetPINHash(newHash); err != nil {
		return err
	}

	fmt.Println("\n✅ PIN changed successfully")
	return nil
}

func runAuthDisable(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Get PIN hash
	storedHash, err := store.GetPINHash()
	if err != nil {
		return err
	}

	// Verify current PIN before disabling
	fmt.Println("To disable PIN authentication, verify your current PIN:")
	if err := auth.Authenticate(storedHash); err != nil {
		return err
	}

	// Delete PIN hash
	if err := store.DeletePINHash(); err != nil {
		return err
	}

	fmt.Println("\n✅ PIN authentication disabled")
	fmt.Println("⚠️  Secrets can now be accessed without PIN verification")

	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	if store.HasPIN() {
		fmt.Println("🔐 PIN authentication: ENABLED")
		fmt.Println("\nSecrets require PIN entry before access.")
		fmt.Println("\nCommands:")
		fmt.Println("  nokey auth change   - Change your PIN")
		fmt.Println("  nokey auth disable  - Disable PIN authentication")
	} else {
		fmt.Println("🔓 PIN authentication: DISABLED")
		fmt.Println("\nSecrets can be accessed without PIN verification.")
		fmt.Println("\nTo enable:")
		fmt.Println("  nokey auth setup")
	}

	return nil
}

// OAuth command implementations

func runAuthOAuthSetup(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	var provider oauth.Provider
	var providerName string

	switch oauthProvider {
	case "github":
		// Create callback server
		callbackServer, err := oauth.NewCallbackServer()
		if err != nil {
			return fmt.Errorf("failed to create callback server: %w", err)
		}
		defer callbackServer.Shutdown(context.Background())

		redirectURL := callbackServer.GetRedirectURL()
		providerName = "github"

		// Create GitHub provider
		provider = oauth.NewGitHubProvider(oauthClientID, oauthClientSecret, redirectURL)

		// Start callback server
		if err := callbackServer.Start(); err != nil {
			return fmt.Errorf("failed to start callback server: %w", err)
		}

		// Get authorization URL
		authURL := provider.GetAuthURL(callbackServer.GetState())

		fmt.Println("🔐 Setting up GitHub OAuth authentication")
		fmt.Println("\nOpening browser for GitHub authorization...")
		fmt.Printf("\nIf the browser doesn't open, visit this URL:\n%s\n\n", authURL)

		// Open browser
		if err := browser.OpenURL(authURL); err != nil {
			fmt.Printf("⚠️  Could not open browser: %v\n", err)
		}

		// Wait for callback (5 minute timeout)
		fmt.Println("Waiting for authorization callback...")
		code, err := callbackServer.WaitForCode(5 * time.Minute)
		if err != nil {
			return fmt.Errorf("authorization failed: %w", err)
		}

		// Exchange code for token
		ctx := context.Background()
		token, err := provider.ExchangeCode(ctx, code)
		if err != nil {
			return fmt.Errorf("failed to exchange authorization code: %w", err)
		}

		// Validate token
		if err := provider.ValidateToken(ctx, token); err != nil {
			return fmt.Errorf("token validation failed: %w", err)
		}

		// Save token
		if err := oauth.SaveToken(store, providerName, token); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}

		// Save client credentials for token refresh
		creds := &oauth.ClientCredentials{
			ClientID:     oauthClientID,
			ClientSecret: oauthClientSecret,
		}
		if err := oauth.SaveClientCredentials(store, providerName, creds); err != nil {
			return fmt.Errorf("failed to save client credentials: %w", err)
		}

		fmt.Println("\n✅ GitHub OAuth authentication configured successfully")
		fmt.Printf("\nToken expires: %s\n", token.Expiry.Format(time.RFC3339))

	case "generic":
		if oauthAuthURL == "" || oauthTokenURL == "" {
			return fmt.Errorf("--auth-url and --token-url are required for generic provider")
		}

		// Create callback server
		callbackServer, err := oauth.NewCallbackServer()
		if err != nil {
			return fmt.Errorf("failed to create callback server: %w", err)
		}
		defer callbackServer.Shutdown(context.Background())

		redirectURL := callbackServer.GetRedirectURL()
		providerName = "generic"

		// Create generic provider
		provider = oauth.NewGenericProvider(
			"generic",
			oauthAuthURL,
			oauthTokenURL,
			oauthUserInfoURL,
			oauthClientID,
			oauthClientSecret,
			oauthScopes,
			redirectURL,
		)

		// Start callback server
		if err := callbackServer.Start(); err != nil {
			return fmt.Errorf("failed to start callback server: %w", err)
		}

		// Get authorization URL
		authURL := provider.GetAuthURL(callbackServer.GetState())

		fmt.Println("🔐 Setting up OAuth authentication")
		fmt.Println("\nOpening browser for authorization...")
		fmt.Printf("\nIf the browser doesn't open, visit this URL:\n%s\n\n", authURL)

		// Open browser
		if err := browser.OpenURL(authURL); err != nil {
			fmt.Printf("⚠️  Could not open browser: %v\n", err)
		}

		// Wait for callback (5 minute timeout)
		fmt.Println("Waiting for authorization callback...")
		code, err := callbackServer.WaitForCode(5 * time.Minute)
		if err != nil {
			return fmt.Errorf("authorization failed: %w", err)
		}

		// Exchange code for token
		ctx := context.Background()
		token, err := provider.ExchangeCode(ctx, code)
		if err != nil {
			return fmt.Errorf("failed to exchange authorization code: %w", err)
		}

		// Validate token
		if err := provider.ValidateToken(ctx, token); err != nil {
			return fmt.Errorf("token validation failed: %w", err)
		}

		// Save token
		if err := oauth.SaveToken(store, providerName, token); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}

		// Save client credentials for token refresh
		creds := &oauth.ClientCredentials{
			ClientID:     oauthClientID,
			ClientSecret: oauthClientSecret,
			AuthURL:      oauthAuthURL,
			TokenURL:     oauthTokenURL,
			UserInfoURL:  oauthUserInfoURL,
			Scopes:       oauthScopes,
		}
		if err := oauth.SaveClientCredentials(store, providerName, creds); err != nil {
			return fmt.Errorf("failed to save client credentials: %w", err)
		}

		fmt.Println("\n✅ OAuth authentication configured successfully")
		fmt.Printf("\nToken expires: %s\n", token.Expiry.Format(time.RFC3339))

	default:
		return fmt.Errorf("unsupported provider: %s (supported: github, generic)", oauthProvider)
	}

	fmt.Println("\nTo use OAuth authentication with exec:")
	fmt.Println("  Set auth.default_method to 'oauth' in ~/.config/nokey/config.yaml")

	return nil
}

func runAuthOAuthStatus(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Check for known providers
	providers := []string{"github", "generic"}
	foundAny := false

	for _, providerName := range providers {
		token, err := oauth.LoadToken(store, providerName)
		if err != nil {
			continue
		}

		foundAny = true
		fmt.Printf("🔐 Provider: %s\n", providerName)
		fmt.Printf("   Token Type: %s\n", token.TokenType)
		fmt.Printf("   Expires: %s\n", token.Expiry.Format(time.RFC3339))

		if token.IsExpired() {
			fmt.Println("   Status: ⚠️  EXPIRED")
			if token.RefreshToken != "" {
				fmt.Println("   Refresh: Available (run 'nokey auth oauth refresh')")
			} else {
				fmt.Println("   Refresh: Not available (run 'nokey auth oauth setup' again)")
			}
		} else {
			expiresIn := time.Until(token.Expiry)
			fmt.Printf("   Status: ✅ VALID (expires in %s)\n", expiresIn.Round(time.Second))
		}

		if len(token.Scopes) > 0 {
			fmt.Printf("   Scopes: %v\n", token.Scopes)
		}
		fmt.Println()
	}

	if !foundAny {
		fmt.Println("🔓 No OAuth tokens configured")
		fmt.Println("\nTo set up OAuth:")
		fmt.Println("  nokey auth oauth setup --provider github --client-id ... --client-secret ...")
	}

	return nil
}

func runAuthOAuthRefresh(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Load existing token
	token, err := oauth.LoadToken(store, oauthProvider)
	if err != nil {
		return fmt.Errorf("no OAuth token found for provider %s: %w", oauthProvider, err)
	}

	if token.RefreshToken == "" {
		return fmt.Errorf("no refresh token available for provider %s (re-run: nokey auth oauth setup --provider %s)", oauthProvider, oauthProvider)
	}

	// Load client credentials
	creds, err := oauth.LoadClientCredentials(store, oauthProvider)
	if err != nil {
		return fmt.Errorf("client credentials not found for provider %s (re-run: nokey auth oauth setup --provider %s): %w", oauthProvider, oauthProvider, err)
	}

	// Create provider based on stored credentials
	var provider oauth.Provider
	ctx := context.Background()

	switch oauthProvider {
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
		return fmt.Errorf("unsupported provider: %s", oauthProvider)
	}

	// Refresh the token
	fmt.Printf("Refreshing OAuth token for provider '%s'...\n", oauthProvider)
	newToken, err := provider.RefreshToken(ctx, token.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Validate the new token
	if err := provider.ValidateToken(ctx, newToken); err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	// Save the refreshed token
	if err := oauth.SaveToken(store, oauthProvider, newToken); err != nil {
		return fmt.Errorf("failed to save refreshed token: %w", err)
	}

	fmt.Printf("✅ OAuth token refreshed successfully\n")
	fmt.Printf("\nNew token expires: %s\n", newToken.Expiry.Format(time.RFC3339))

	return nil
}

func runAuthOAuthLogout(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Delete token
	if err := oauth.DeleteToken(store, oauthProvider); err != nil {
		return fmt.Errorf("failed to remove OAuth token: %w", err)
	}

	// Delete client credentials
	if err := oauth.DeleteClientCredentials(store, oauthProvider); err != nil {
		// Don't fail if credentials not found - they might not have been saved
		fmt.Fprintf(os.Stderr, "Warning: failed to remove client credentials: %v\n", err)
	}

	fmt.Printf("✅ OAuth token for provider '%s' has been removed\n", oauthProvider)
	return nil
}
