package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	kring "github.com/99designs/keyring"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/oauth"
)

// --- PIN auth ---

func TestRunAuthSetup_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	// Mock SetupPIN to return a fake hash
	old := authSetupPINFn
	t.Cleanup(func() { authSetupPINFn = old })
	authSetupPINFn = func() (string, error) {
		return "fake-hash-value", nil
	}

	output := captureStdout(t, func() {
		if err := runAuthSetup(nil, nil); err != nil {
			t.Fatalf("runAuthSetup: %v", err)
		}
	})
	if !strings.Contains(output, "PIN authentication enabled") {
		t.Errorf("output = %q, want success message", output)
	}

	// Verify hash was stored
	if !store.HasPIN() {
		t.Error("store should have PIN after setup")
	}
}

func TestRunAuthSetup_AlreadyConfigured(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	// Pre-set a PIN hash
	store.SetPINHash("existing-hash")

	err := runAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "PIN already configured") {
		t.Errorf("expected 'PIN already configured' error, got: %v", err)
	}
}

func TestRunAuthChange_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("old-hash")

	old := authChangePINFn
	t.Cleanup(func() { authChangePINFn = old })
	authChangePINFn = func(oldHash string) (string, error) {
		if oldHash != "old-hash" {
			t.Errorf("changePIN received wrong old hash: %q", oldHash)
		}
		return "new-hash", nil
	}

	output := captureStdout(t, func() {
		if err := runAuthChange(nil, nil); err != nil {
			t.Fatalf("runAuthChange: %v", err)
		}
	})
	if !strings.Contains(output, "PIN changed successfully") {
		t.Errorf("output = %q, want success message", output)
	}

	hash, _ := store.GetPINHash()
	if hash != "new-hash" {
		t.Errorf("stored hash = %q, want %q", hash, "new-hash")
	}
}

func TestRunAuthDisable_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("my-hash")

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		if storedHash != "my-hash" {
			t.Errorf("authenticate received wrong hash: %q", storedHash)
		}
		return nil
	}

	output := captureStdout(t, func() {
		if err := runAuthDisable(nil, nil); err != nil {
			t.Fatalf("runAuthDisable: %v", err)
		}
	})
	if !strings.Contains(output, "PIN authentication disabled") {
		t.Errorf("output = %q, want success message", output)
	}

	if store.HasPIN() {
		t.Error("store should not have PIN after disable")
	}
}

func TestRunAuthStatus_Enabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("some-hash")

	output := captureStdout(t, func() {
		if err := runAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "ENABLED") {
		t.Errorf("output = %q, want ENABLED", output)
	}
}

func TestRunAuthStatus_Disabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "DISABLED") {
		t.Errorf("output = %q, want DISABLED", output)
	}
}

// --- OAuth ---

func TestNewOAuthProvider_GitHub(t *testing.T) {
	creds := &oauth.ClientCredentials{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
	}
	provider := newOAuthProvider("github", creds, "http://localhost/callback")
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewOAuthProvider_Generic(t *testing.T) {
	creds := &oauth.ClientCredentials{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		AuthURL:      "https://auth.example.com/authorize",
		TokenURL:     "https://auth.example.com/token",
		UserInfoURL:  "https://auth.example.com/userinfo",
		Scopes:       []string{"openid", "profile"},
	}
	provider := newOAuthProvider("generic", creds, "http://localhost/callback")
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestRunAuthOAuthStatus_NoTokens(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runAuthOAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthOAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "No OAuth tokens configured") {
		t.Errorf("output = %q, want 'No OAuth tokens configured'", output)
	}
}

func TestRunAuthOAuthLogout_NoToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	err := runAuthOAuthLogout(nil, nil)
	if err == nil {
		t.Fatal("expected error when no token exists")
	}
}

func TestRunAuthOAuthSetup_UnsupportedProvider(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "unsupported"

	err := runAuthOAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported provider") {
		t.Errorf("expected 'unsupported provider' error, got: %v", err)
	}
}

func TestRunAuthOAuthSetup_GenericMissingURLs(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	oldProvider := oauthProvider
	oldAuthURL := oauthAuthURL
	oldTokenURL := oauthTokenURL
	t.Cleanup(func() {
		oauthProvider = oldProvider
		oauthAuthURL = oldAuthURL
		oauthTokenURL = oldTokenURL
	})
	oauthProvider = "generic"
	oauthAuthURL = ""
	oauthTokenURL = ""

	err := runAuthOAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--auth-url and --token-url are required") {
		t.Errorf("expected missing URL error, got: %v", err)
	}
}

func TestRunAuthOAuthRefresh_NoToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	err := runAuthOAuthRefresh(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no OAuth token found") {
		t.Errorf("expected 'no OAuth token found' error, got: %v", err)
	}
}

func TestRunAuthOAuthStatus_WithValidToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runAuthOAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthOAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "github") {
		t.Errorf("output missing provider name: %q", output)
	}
	if !strings.Contains(output, "VALID") {
		t.Errorf("output missing VALID status: %q", output)
	}
}

func TestRunAuthOAuthStatus_WithExpiredToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "expired-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runAuthOAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthOAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "EXPIRED") {
		t.Errorf("output missing EXPIRED status: %q", output)
	}
	if !strings.Contains(output, "Available") {
		t.Errorf("output missing refresh available: %q", output)
	}
}

func TestRunAuthOAuthStatus_WithExpiredNoRefresh(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken: "expired-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runAuthOAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthOAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "EXPIRED") {
		t.Errorf("output missing EXPIRED: %q", output)
	}
	if !strings.Contains(output, "Not available") {
		t.Errorf("output missing 'Not available': %q", output)
	}
}

func TestRunAuthOAuthStatus_WithScopes(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
		Scopes:      []string{"read", "write"},
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runAuthOAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthOAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "Scopes") {
		t.Errorf("output missing scopes: %q", output)
	}
}

func TestRunAuthOAuthLogout_WithToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken: "to-delete",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	output := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := runAuthOAuthLogout(nil, nil); err != nil {
				t.Fatalf("runAuthOAuthLogout: %v", err)
			}
		})
	})
	if !strings.Contains(output, "has been removed") {
		t.Errorf("output = %q, want 'has been removed'", output)
	}

	// Verify token is deleted
	_, err := oauth.LoadToken(store, "github")
	if err == nil {
		t.Error("token should be deleted after logout")
	}
}

func TestRunAuthOAuthRefresh_NoRefreshToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "valid-token",
		TokenType:    "Bearer",
		RefreshToken: "", // No refresh token
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	err := runAuthOAuthRefresh(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no refresh token available") {
		t.Errorf("expected 'no refresh token available' error, got: %v", err)
	}
}

func TestRunAuthOAuthRefresh_NoCreds(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "valid-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	// Do NOT save client credentials

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	err := runAuthOAuthRefresh(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "client credentials not found") {
		t.Errorf("expected 'client credentials not found' error, got: %v", err)
	}
}

func TestRunAuthChange_NoPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	err := runAuthChange(nil, nil)
	if err == nil {
		t.Fatal("expected error when no PIN configured")
	}
}

func TestRunAuthDisable_NoPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	err := runAuthDisable(nil, nil)
	if err == nil {
		t.Fatal("expected error when no PIN configured")
	}
}

func TestRunAuthSetup_SetupPINError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authSetupPINFn
	t.Cleanup(func() { authSetupPINFn = old })
	authSetupPINFn = func() (string, error) {
		return "", fmt.Errorf("pin entry failed")
	}

	err := runAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "pin entry failed") {
		t.Errorf("expected 'pin entry failed' error, got: %v", err)
	}
}

func TestRunAuthChange_ChangePINError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("old-hash")

	old := authChangePINFn
	t.Cleanup(func() { authChangePINFn = old })
	authChangePINFn = func(oldHash string) (string, error) {
		return "", fmt.Errorf("wrong pin")
	}

	err := runAuthChange(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "wrong pin") {
		t.Errorf("expected 'wrong pin' error, got: %v", err)
	}
}

func TestRunAuthDisable_AuthFailed(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("my-hash")

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		return fmt.Errorf("auth failed")
	}

	err := runAuthDisable(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("expected 'auth failed' error, got: %v", err)
	}
}

func TestRunAuthStatus_WithSession(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("some-hash")

	output := captureStdout(t, func() {
		if err := runAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "ENABLED") {
		t.Errorf("output = %q, want ENABLED", output)
	}
}

func TestRunAuthOAuthRefresh_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "old-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	creds := &oauth.ClientCredentials{ClientID: "cid", ClientSecret: "csec"}
	if err := oauth.SaveClientCredentials(store, "github", creds); err != nil {
		t.Fatalf("SaveClientCredentials: %v", err)
	}

	newToken := &oauth.Token{
		AccessToken:  "fresh-token",
		TokenType:    "Bearer",
		RefreshToken: "new-refresh",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	withMockOAuthProvider(t, &mockOAuthProvider{
		refreshFn: func(ctx context.Context, rt string) (*oauth.Token, error) {
			return newToken, nil
		},
	})

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	output := captureStdout(t, func() {
		if err := runAuthOAuthRefresh(nil, nil); err != nil {
			t.Fatalf("runAuthOAuthRefresh: %v", err)
		}
	})
	if !strings.Contains(output, "refreshed successfully") {
		t.Errorf("output = %q, want 'refreshed successfully'", output)
	}

	// Verify the new token was saved
	saved, err := oauth.LoadToken(store, "github")
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if saved.AccessToken != "fresh-token" {
		t.Errorf("saved token = %q, want 'fresh-token'", saved.AccessToken)
	}
}

func TestRunAuthOAuthRefresh_RefreshError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "old-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	creds := &oauth.ClientCredentials{ClientID: "cid", ClientSecret: "csec"}
	if err := oauth.SaveClientCredentials(store, "github", creds); err != nil {
		t.Fatalf("SaveClientCredentials: %v", err)
	}

	withMockOAuthProvider(t, &mockOAuthProvider{
		refreshFn: func(ctx context.Context, rt string) (*oauth.Token, error) {
			return nil, fmt.Errorf("provider error")
		},
	})

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	_ = captureStdout(t, func() {
		err := runAuthOAuthRefresh(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "failed to refresh") {
			t.Errorf("expected 'failed to refresh' error, got: %v", err)
		}
	})
}

func TestRunAuthOAuthRefresh_ValidateError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "old-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	creds := &oauth.ClientCredentials{ClientID: "cid", ClientSecret: "csec"}
	if err := oauth.SaveClientCredentials(store, "github", creds); err != nil {
		t.Fatalf("SaveClientCredentials: %v", err)
	}

	newToken := &oauth.Token{
		AccessToken: "bad-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	withMockOAuthProvider(t, &mockOAuthProvider{
		refreshFn: func(ctx context.Context, rt string) (*oauth.Token, error) {
			return newToken, nil
		},
		validateFn: func(ctx context.Context, token *oauth.Token) error {
			return fmt.Errorf("validation error")
		},
	})

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	_ = captureStdout(t, func() {
		err := runAuthOAuthRefresh(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Errorf("expected 'validation failed' error, got: %v", err)
		}
	})
}

func TestRunAuthOAuthRefresh_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthOAuthRefresh(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthOAuthSetup_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthOAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthOAuthLogout_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthOAuthLogout(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthSetup_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthChange_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthChange(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthDisable_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthDisable(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthStatus_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthStatus(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthOAuthStatus_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthOAuthStatus(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

// --- auth setup/change/disable SetPINHash/DeletePINHash errors ---

func TestRunAuthSetup_SetPINHashError(t *testing.T) {
	// Use errorSetRing so SetPINHash (which calls ring.Set) fails
	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authSetupPINFn
	t.Cleanup(func() { authSetupPINFn = old })
	authSetupPINFn = func() (string, error) {
		return "new-hash", nil
	}

	err := runAuthSetup(nil, nil)
	if err == nil {
		t.Fatal("expected error when SetPINHash fails")
	}
	if !strings.Contains(err.Error(), "set failed") {
		t.Errorf("error = %v, want 'set failed'", err)
	}
}

func TestRunAuthChange_SetPINHashError(t *testing.T) {
	// Pre-store PIN hash directly in mockRing, then wrap with errorSetRing
	ring := newMockRing()
	ring.items["__nokey_pin_hash__"] = kring.Item{
		Key:  "__nokey_pin_hash__",
		Data: []byte("old-hash"),
	}
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authChangePINFn
	t.Cleanup(func() { authChangePINFn = old })
	authChangePINFn = func(oldHash string) (string, error) {
		return "new-hash", nil
	}

	err := runAuthChange(nil, nil)
	if err == nil {
		t.Fatal("expected error when SetPINHash fails")
	}
	if !strings.Contains(err.Error(), "set failed") {
		t.Errorf("error = %v, want 'set failed'", err)
	}
}

func TestRunAuthDisable_DeletePINHashError(t *testing.T) {
	// Pre-store PIN hash, then wrap with errorRemoveRing
	ring := newMockRing()
	ring.items["__nokey_pin_hash__"] = kring.Item{
		Key:  "__nokey_pin_hash__",
		Data: []byte("my-hash"),
	}
	store := nkeyring.NewWithRing(&errorRemoveRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error { return nil }

	err := runAuthDisable(nil, nil)
	if err == nil {
		t.Fatal("expected error when DeletePINHash fails")
	}
	if !strings.Contains(err.Error(), "remove failed") {
		t.Errorf("error = %v, want 'remove failed'", err)
	}
}

// oauthSetupCapture is a local Provider mock that captures the state passed to GetAuthURL.
type oauthSetupCapture struct {
	stateCh chan string
	token   *oauth.Token
}

func (m *oauthSetupCapture) GetAuthURL(state string) string {
	m.stateCh <- state
	return "http://mock/auth?state=" + state
}
func (m *oauthSetupCapture) ExchangeCode(_ context.Context, _ string) (*oauth.Token, error) {
	return m.token, nil
}
func (m *oauthSetupCapture) RefreshToken(_ context.Context, _ string) (*oauth.Token, error) {
	return nil, nil
}
func (m *oauthSetupCapture) ValidateToken(_ context.Context, _ *oauth.Token) error { return nil }
func (m *oauthSetupCapture) GetProviderName() string                               { return "github" }

func TestRunAuthOAuthSetup_GitHub_HappyPath(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken:  "access123",
		RefreshToken: "refresh123",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	stateCh := make(chan string, 1)
	redirectURLCh := make(chan string, 1)

	old := newOAuthProviderFn
	t.Cleanup(func() { newOAuthProviderFn = old })
	newOAuthProviderFn = func(name string, creds *oauth.ClientCredentials, redirectURL string) oauth.Provider {
		redirectURLCh <- redirectURL
		return &oauthSetupCapture{stateCh: stateCh, token: tok}
	}

	oldProvider := oauthProvider
	t.Cleanup(func() { oauthProvider = oldProvider })
	oauthProvider = "github"

	errCh := make(chan error, 1)
	go func() {
		errCh <- runAuthOAuthSetup(nil, nil)
	}()

	// Wait for provider to be created (redirect URL known) then for state to be captured.
	redirectURL := <-redirectURLCh
	state := <-stateCh

	// Simulate browser callback.
	resp, err := http.Get(redirectURL + "?code=authcode&state=" + state)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("runAuthOAuthSetup: %v", err)
	}

	// Verify token was persisted.
	saved, err := oauth.LoadToken(store, "github")
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if saved.AccessToken != tok.AccessToken {
		t.Errorf("access token = %q, want %q", saved.AccessToken, tok.AccessToken)
	}
}

func TestRunAuthOAuthSetup_Generic_HappyPath(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tok := &oauth.Token{
		AccessToken: "gen-access",
		TokenType:   "bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	stateCh := make(chan string, 1)
	redirectURLCh := make(chan string, 1)

	old := newOAuthProviderFn
	t.Cleanup(func() { newOAuthProviderFn = old })
	newOAuthProviderFn = func(name string, creds *oauth.ClientCredentials, redirectURL string) oauth.Provider {
		redirectURLCh <- redirectURL
		return &oauthSetupCapture{stateCh: stateCh, token: tok}
	}

	oldProvider := oauthProvider
	oldAuthURL := oauthAuthURL
	oldTokenURL := oauthTokenURL
	t.Cleanup(func() {
		oauthProvider = oldProvider
		oauthAuthURL = oldAuthURL
		oauthTokenURL = oldTokenURL
	})
	oauthProvider = "generic"
	oauthAuthURL = "https://example.com/auth"
	oauthTokenURL = "https://example.com/token"

	errCh := make(chan error, 1)
	go func() {
		errCh <- runAuthOAuthSetup(nil, nil)
	}()

	redirectURL := <-redirectURLCh
	state := <-stateCh

	resp, err := http.Get(redirectURL + "?code=gencode&state=" + state)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("runAuthOAuthSetup generic: %v", err)
	}

	saved, err := oauth.LoadToken(store, "generic")
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if saved.AccessToken != tok.AccessToken {
		t.Errorf("access token = %q, want %q", saved.AccessToken, tok.AccessToken)
	}
}
