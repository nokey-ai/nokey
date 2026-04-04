package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/oauth"
	"github.com/nokey-ai/nokey/internal/session"
	"github.com/spf13/cobra"
)

// --- confirmSecrets ---

func TestConfirmSecrets_EmptySecrets(t *testing.T) {
	confirmed, err := confirmSecrets(map[string]string{}, "cmd")
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed {
		t.Error("empty secrets should return true")
	}
}

func TestConfirmSecrets_UserInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"yes_short", "y\n", true},
		{"yes_full", "yes\n", true},
		{"no", "n\n", false},
		{"default_empty", "\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withStdin(t, tt.input)
			secrets := map[string]string{"API_KEY": "value"}
			confirmed, err := confirmSecrets(secrets, "test-cmd")
			if err != nil {
				t.Fatal(err)
			}
			if confirmed != tt.want {
				t.Errorf("confirmSecrets with input %q = %v, want %v", tt.input, confirmed, tt.want)
			}
		})
	}
}

// --- runExec ---

func TestRunExec_AuthNone(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("MY_SECRET", "secret-value")

	withExecGlobals(t)

	var capturedExitCode int
	osExitFn = func(code int) { capturedExitCode = code }
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if command != "echo" {
			t.Errorf("command = %q, want 'echo'", command)
		}
		if secrets["MY_SECRET"] != "secret-value" {
			t.Errorf("secret not injected correctly")
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	// Create a minimal cobra.Command with the redact flag
	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if capturedExitCode != 0 {
		t.Errorf("exit code = %d, want 0", capturedExitCode)
	}
}

func TestRunExec_AuthNone_NonZeroExit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	withExecGlobals(t)

	var capturedExitCode int
	osExitFn = func(code int) { capturedExitCode = code }
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 42, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"exit42"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if capturedExitCode != 42 {
		t.Errorf("exit code = %d, want 42", capturedExitCode)
	}
}

func TestRunExec_WithRedact(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	withExecGlobals(t)

	var calledRedact bool
	osExitFn = func(_ int) {}
	redactRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		calledRedact = true
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")
	cmd.Flags().Set("redact", "true")

	err := runExec(cmd, []string{"cmd"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !calledRedact {
		t.Error("expected redact.Run to be called when --redact is set")
	}
}

func TestRunExec_InvalidAuthMethod(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = ""
	withTestConfig(t, c)

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "invalid"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "invalid auth method") {
		t.Errorf("expected 'invalid auth method' error, got: %v", err)
	}
}

func TestRunExec_ExecError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	withExecGlobals(t)

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 1, fmt.Errorf("exec failed")
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"failing-cmd"})
	if err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Errorf("expected 'exec failed' error, got: %v", err)
	}
}

func TestRunExec_WithAudit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	withExecGlobals(t)

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	// Audit recording may fail due to missing encryption key in mock,
	// but should not cause runExec to error.
	_ = captureStderr(t, func() {
		err := runExec(cmd, []string{"audited-cmd"})
		if err != nil {
			t.Fatalf("runExec: %v", err)
		}
	})
}

func TestRunExec_ConfirmAborted(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
	skipConfirm = false
	authMethod = "none"

	withStdin(t, "n\n")

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Errorf("expected 'aborted' error, got: %v", err)
	}
}

func TestRunExec_NoSecretsWarning(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	// No secrets stored

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	stderr := captureStderr(t, func() {
		err := runExec(cmd, []string{"echo"})
		if err != nil {
			t.Fatalf("runExec: %v", err)
		}
	})
	if !strings.Contains(stderr, "no secrets") {
		t.Errorf("stderr = %q, want warning about no secrets", stderr)
	}
}

func TestRunExec_RedactByDefault(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	c.RedactByDefault = true
	withTestConfig(t, c)

	store.Set("KEY", "val")

	withExecGlobals(t)

	var calledRedact bool
	osExitFn = func(_ int) {}
	redactRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		calledRedact = true
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	// Don't set --redact flag explicitly; config default should take over.
	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"cmd"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !calledRedact {
		t.Error("expected redact.Run to be called when RedactByDefault is true")
	}
}

// --- runExec auth paths ---

func TestRunExec_PINAuthNoPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "pin"
	withTestConfig(t, c)

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "pin"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "PIN authentication failed") {
		t.Errorf("expected 'PIN authentication failed' error, got: %v", err)
	}
}

func TestRunExec_OAuthAuthNoToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "oauth"
	withTestConfig(t, c)

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "oauth"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "OAuth authentication failed") {
		t.Errorf("expected 'OAuth authentication failed' error, got: %v", err)
	}
}

func TestRunExec_BothAuthNoToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "both"
	withTestConfig(t, c)

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "both"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "OAuth authentication failed") {
		t.Errorf("expected 'OAuth authentication failed' error, got: %v", err)
	}
}

func TestRunExec_LegacyPINDetection(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = ""
	c.RequireAuth = true
	withTestConfig(t, c)

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "" // No flag override — should detect PIN from RequireAuth

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	// Should try PIN auth and fail because no PIN hash is stored
	if err == nil || !strings.Contains(err.Error(), "PIN authentication failed") {
		t.Errorf("expected 'PIN authentication failed' error, got: %v", err)
	}
}

func TestRunExec_ExecErrorWithAudit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	withExecGlobals(t)

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 1, fmt.Errorf("exec failed")
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	_ = captureStderr(t, func() {
		err := runExec(cmd, []string{"failing-cmd"})
		if err == nil || !strings.Contains(err.Error(), "exec failed") {
			t.Errorf("expected 'exec failed' error, got: %v", err)
		}
	})
}

func TestRunExec_FilterExcept(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("A", "1")
	store.Set("B", "2")
	store.Set("C", "3")

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	oldExcept := exceptSecrets
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
		exceptSecrets = oldExcept
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if _, ok := secrets["B"]; ok {
			t.Error("secret B should be excluded")
		}
		if len(secrets) != 2 {
			t.Errorf("expected 2 secrets, got %d", len(secrets))
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"
	exceptSecrets = "B"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
}

// --- validateOAuthToken ---

func TestValidateOAuthToken_NoProvider(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	err := validateOAuthToken(store)
	if err == nil || !strings.Contains(err.Error(), "no OAuth token found") {
		t.Errorf("expected 'no OAuth token found' error, got: %v", err)
	}
}

func TestValidateOAuthToken_GitHubEnabled(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	c.Auth.OAuth.GitHub.Enabled = true
	withTestConfig(t, c)

	err := validateOAuthToken(store)
	if err == nil || !strings.Contains(err.Error(), "no OAuth token found") {
		t.Errorf("expected 'no OAuth token found' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "github") {
		t.Errorf("error should mention 'github', got: %v", err)
	}
}

func TestValidateOAuthToken_CustomEnabled(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	c.Auth.OAuth.Custom.Enabled = true
	withTestConfig(t, c)

	err := validateOAuthToken(store)
	if err == nil || !strings.Contains(err.Error(), "no OAuth token found") {
		t.Errorf("expected 'no OAuth token found' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "generic") {
		t.Errorf("error should mention 'generic', got: %v", err)
	}
}

func TestValidateOAuthToken_ExpiredNoRefresh(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	// Store an expired token with no refresh token
	expiredToken := &oauth.Token{
		AccessToken:  "expired-access-token",
		TokenType:    "Bearer",
		RefreshToken: "",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", expiredToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	err := validateOAuthToken(store)
	if err == nil || !strings.Contains(err.Error(), "expired and no refresh token") {
		t.Errorf("expected 'expired and no refresh token' error, got: %v", err)
	}
}

func TestValidateOAuthToken_ExpiredWithRefreshNoCreds(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	// Store an expired token WITH refresh token but no client credentials
	expiredToken := &oauth.Token{
		AccessToken:  "expired-access-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", expiredToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	err := validateOAuthToken(store)
	if err == nil || !strings.Contains(err.Error(), "client credentials not found") {
		t.Errorf("expected 'client credentials not found' error, got: %v", err)
	}
}

func TestValidateOAuthToken_ValidToken(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	// Store a valid (not expired) token
	validToken := &oauth.Token{
		AccessToken:  "valid-access-token",
		TokenType:    "Bearer",
		RefreshToken: "",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", validToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	err := validateOAuthToken(store)
	if err != nil {
		t.Errorf("expected no error for valid token, got: %v", err)
	}
}

func TestValidateOAuthToken_RefreshSuccess(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	// Store an expired token WITH refresh token
	expiredToken := &oauth.Token{
		AccessToken:  "expired-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", expiredToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	// Store client credentials
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
			if rt != "refresh-me" {
				t.Errorf("refresh token = %q, want 'refresh-me'", rt)
			}
			return newToken, nil
		},
	})

	_ = captureStderr(t, func() {
		err := validateOAuthToken(store)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	// Verify the new token was saved
	saved, err := oauth.LoadToken(store, "github")
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if saved.AccessToken != "fresh-token" {
		t.Errorf("saved token = %q, want 'fresh-token'", saved.AccessToken)
	}
}

func TestValidateOAuthToken_RefreshError(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	expiredToken := &oauth.Token{
		AccessToken:  "expired-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", expiredToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	creds := &oauth.ClientCredentials{ClientID: "cid", ClientSecret: "csec"}
	if err := oauth.SaveClientCredentials(store, "github", creds); err != nil {
		t.Fatalf("SaveClientCredentials: %v", err)
	}

	withMockOAuthProvider(t, &mockOAuthProvider{
		refreshFn: func(ctx context.Context, rt string) (*oauth.Token, error) {
			return nil, fmt.Errorf("refresh failed")
		},
	})

	_ = captureStderr(t, func() {
		err := validateOAuthToken(store)
		if err == nil || !strings.Contains(err.Error(), "failed to refresh") {
			t.Errorf("expected 'failed to refresh' error, got: %v", err)
		}
	})
}

func TestValidateOAuthToken_ValidateAfterRefreshError(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	withTestConfig(t, c)

	expiredToken := &oauth.Token{
		AccessToken:  "expired-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-me",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", expiredToken); err != nil {
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
			return fmt.Errorf("token invalid")
		},
	})

	_ = captureStderr(t, func() {
		err := validateOAuthToken(store)
		if err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Errorf("expected 'validation failed' error, got: %v", err)
		}
	})
}

func TestRunExec_OAuthAuthValid(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "oauth"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	// Store a valid token
	validToken := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", validToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if secrets["KEY"] != "val" {
			t.Errorf("secret not injected")
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "oauth"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec with oauth: %v", err)
	}
}

func TestRunExec_BothAuthValid(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "both"
	c.Auth.SessionTTL = "5m"
	withTestConfig(t, c)

	store.Set("KEY", "val")
	store.SetPINHash("hash")

	// Store a valid token
	validToken := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", validToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	// Create a valid session so we don't need interactive PIN entry
	_ = session.Create("hash")

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if secrets["KEY"] != "val" {
			t.Errorf("secret not injected")
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "both"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec with both: %v", err)
	}
}

func TestRunExec_PINAuthWithSession(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "pin"
	c.Auth.SessionTTL = "5m"
	withTestConfig(t, c)

	store.Set("KEY", "val")
	store.SetPINHash("hash")

	// Create a valid session to avoid interactive PIN entry
	_ = session.Create("hash")

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if secrets["KEY"] != "val" {
			t.Errorf("secret not injected")
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "pin"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec with pin session: %v", err)
	}
}

func TestRunExec_BothAuthPINFailed(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "both"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	// Store a valid token but NO PIN hash
	validToken := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", validToken); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "both"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "PIN authentication failed") {
		t.Errorf("expected 'PIN authentication failed' error, got: %v", err)
	}
}

func TestRunExec_InvalidSessionTTL(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	c.Auth.SessionTTL = "invalid-ttl"
	withTestConfig(t, c)

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "config error") {
		t.Errorf("expected 'config error' error, got: %v", err)
	}
}

func TestRunExec_FilterError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	oldSkip := skipConfirm
	oldMethod := authMethod
	oldOnly := onlySecrets
	oldExcept := exceptSecrets
	t.Cleanup(func() {
		skipConfirm = oldSkip
		authMethod = oldMethod
		onlySecrets = oldOnly
		exceptSecrets = oldExcept
	})
	skipConfirm = true
	authMethod = "none"
	onlySecrets = "A"
	exceptSecrets = "B" // Both set → error

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "cannot use both") {
		t.Errorf("expected 'cannot use both' error, got: %v", err)
	}
}

func TestRunExec_FilterNotFound(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	oldSkip := skipConfirm
	oldMethod := authMethod
	oldOnly := onlySecrets
	t.Cleanup(func() {
		skipConfirm = oldSkip
		authMethod = oldMethod
		onlySecrets = oldOnly
	})
	skipConfirm = true
	authMethod = "none"
	onlySecrets = "NONEXISTENT"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("expected 'secret not found' error, got: %v", err)
	}
}

func TestRunExec_FilterOnly(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("A", "1")
	store.Set("B", "2")
	store.Set("C", "3")

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	oldOnly := onlySecrets
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
		onlySecrets = oldOnly
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if len(secrets) != 1 {
			t.Errorf("expected 1 secret, got %d", len(secrets))
		}
		if secrets["A"] != "1" {
			t.Errorf("expected secret A=1, got %v", secrets)
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"
	onlySecrets = "A"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
}

func TestRunExec_WithRedactFlag(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	oldRedact := redactRunFn
	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	oldEnableRedact := enableRedact
	t.Cleanup(func() {
		redactRunFn = oldRedact
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
		enableRedact = oldEnableRedact
	})

	redactCalled := false
	osExitFn = func(_ int) {}
	redactRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		redactCalled = true
		return 0, nil
	}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		t.Error("execRunFn should not be called when redact is enabled")
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"
	enableRedact = true

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")
	cmd.Flags().Set("redact", "true")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !redactCalled {
		t.Error("redactRunFn should have been called")
	}
}

func TestRunExec_OAuthAuthWithValidToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "oauth"
	withTestConfig(t, c)

	store.Set("KEY", "val")

	// Store a valid (not expired) OAuth token
	tok := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		if secrets["KEY"] != "val" {
			t.Errorf("expected KEY=val, got %v", secrets)
		}
		return 0, nil
	}
	skipConfirm = true
	authMethod = "" // Use config default

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
}

func TestRunExec_BothAuthWithValidSession(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "both"
	c.Auth.SessionTTL = "15m"
	withTestConfig(t, c)

	store.Set("KEY", "val")
	store.SetPINHash("both-hash")

	// Create a valid session for PIN
	if err := session.Create("both-hash"); err != nil {
		t.Fatalf("session.Create: %v", err)
	}
	t.Cleanup(func() { _ = session.Clear() })

	// Store a valid OAuth token
	tok := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 0, nil
	}
	skipConfirm = true
	authMethod = "" // Use config default

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
}

func TestRunExec_ConfigRedactByDefault(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	c.RedactByDefault = true
	withTestConfig(t, c)

	store.Set("KEY", "val")

	oldRedact := redactRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		redactRunFn = oldRedact
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})

	redactCalled := false
	osExitFn = func(_ int) {}
	redactRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		redactCalled = true
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")
	// Don't set --redact flag, let config default kick in

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !redactCalled {
		t.Error("redactRunFn should have been called when RedactByDefault is true")
	}
}

func TestConfirmSecrets_Empty(t *testing.T) {
	confirmed, err := confirmSecrets(map[string]string{}, "echo")
	if err != nil {
		t.Fatalf("confirmSecrets: %v", err)
	}
	if !confirmed {
		t.Error("empty secrets should auto-confirm")
	}
}

func TestConfirmSecrets_UserConfirms(t *testing.T) {
	withStdin(t, "y\n")

	confirmed, err := confirmSecrets(map[string]string{"KEY": "val"}, "test-cmd")
	if err != nil {
		t.Fatalf("confirmSecrets: %v", err)
	}
	if !confirmed {
		t.Error("expected confirmed with 'y' input")
	}
}

func TestConfirmSecrets_UserDenies(t *testing.T) {
	withStdin(t, "n\n")

	confirmed, err := confirmSecrets(map[string]string{"KEY": "val"}, "test-cmd")
	if err != nil {
		t.Fatalf("confirmSecrets: %v", err)
	}
	if confirmed {
		t.Error("expected not confirmed with 'n' input")
	}
}

func TestRunExec_SkipConfirmYes(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("K", "v")

	c := config.DefaultConfig()
	withTestConfig(t, c)

	oldExec := execRunFn
	t.Cleanup(func() { execRunFn = oldExec })
	execRunFn = func(name string, args []string, env map[string]string, extra ...string) (int, error) {
		return 0, nil
	}

	oldExit := osExitFn
	t.Cleanup(func() { osExitFn = oldExit })
	osExitFn = func(code int) {}

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = true

	cmd := &cobra.Command{}
	cmd.Flags().Bool("redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExec_AbortConfirm(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("K", "v")

	c := config.DefaultConfig()
	withTestConfig(t, c)

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = false

	withStdin(t, "n\n")

	cmd := &cobra.Command{}
	cmd.Flags().Bool("redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error = %v, want 'aborted'", err)
	}
}

func TestRunExec_IsolateNoPolicies(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("S", "v")

	c := config.DefaultConfig()
	withTestConfig(t, c)

	oldIsolate := enableIsolate
	t.Cleanup(func() { enableIsolate = oldIsolate })
	enableIsolate = true

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = true

	cmd := &cobra.Command{}
	cmd.Flags().Bool("redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil {
		t.Fatal("expected error for isolate with no policies")
	}
	if !strings.Contains(err.Error(), "proxy rule") {
		t.Errorf("error = %v, want 'proxy rule'", err)
	}
}

func TestRunExec_AuditOnSuccess(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	store.Set("AK", "val")

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	oldExec := execRunFn
	t.Cleanup(func() { execRunFn = oldExec })
	execRunFn = func(name string, args []string, env map[string]string, extra ...string) (int, error) {
		return 0, nil
	}

	oldExit := osExitFn
	t.Cleanup(func() { osExitFn = oldExit })
	osExitFn = func(code int) {}

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = true

	cmd := &cobra.Command{}
	cmd.Flags().Bool("redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExec_NonZeroExitCode(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("K", "v")

	c := config.DefaultConfig()
	withTestConfig(t, c)

	oldExec := execRunFn
	t.Cleanup(func() { execRunFn = oldExec })
	execRunFn = func(name string, args []string, env map[string]string, extra ...string) (int, error) {
		return 42, nil
	}

	exitCode := -1
	oldExit := osExitFn
	t.Cleanup(func() { osExitFn = oldExit })
	osExitFn = func(code int) { exitCode = code }

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = true

	cmd := &cobra.Command{}
	cmd.Flags().Bool("redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exitCode = %d, want 42", exitCode)
	}
}

func TestValidateOAuthToken_NotExpired(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Auth.OAuth.GitHub.Enabled = true
	withTestConfig(t, c)

	tok := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	err := validateOAuthToken(store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupIsolationProxy_ValidRules(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create policies.yaml with proxy rules
	configDir := fmt.Sprintf("%s/.config/nokey", dir)
	os.MkdirAll(configDir, 0700)
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_KEY"
`
	os.WriteFile(configDir+"/policies.yaml", []byte(polYAML), 0600)

	secrets := map[string]string{"MY_KEY": "secret-val"}
	envVars, cleanup, err := setupIsolationProxy(secrets)
	if err != nil {
		t.Fatalf("setupIsolationProxy: %v", err)
	}
	defer cleanup()

	if len(envVars) == 0 {
		t.Fatal("expected env vars from isolation proxy")
	}

	// Should include http_proxy, https_proxy, SSL_CERT_FILE, etc.
	found := false
	for _, ev := range envVars {
		if strings.HasPrefix(ev, "http_proxy=") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected http_proxy in env vars, got: %v", envVars)
	}
}

func TestSetupIsolationProxy_NoRules(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create empty config dir with no policies
	configDir := fmt.Sprintf("%s/.config/nokey", dir)
	os.MkdirAll(configDir, 0700)

	secrets := map[string]string{"K": "v"}
	_, _, err := setupIsolationProxy(secrets)
	if err == nil || !strings.Contains(err.Error(), "proxy rule") {
		t.Errorf("expected proxy rule error, got: %v", err)
	}
}

func TestRunExec_BothAuthWithPINSession(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("S", "val")

	c := config.DefaultConfig()
	c.Auth.OAuth.GitHub.Enabled = true
	withTestConfig(t, c)

	// Set up PIN + valid session
	store.SetPINHash("pin-hash")
	session.Create("pin-hash")

	// Save valid OAuth token
	tok := &oauth.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	if err := oauth.SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	oldMethod := authMethod
	t.Cleanup(func() { authMethod = oldMethod })
	authMethod = "both"

	oldExec := execRunFn
	t.Cleanup(func() { execRunFn = oldExec })
	execRunFn = func(name string, args []string, env map[string]string, extra ...string) (int, error) {
		return 0, nil
	}

	oldExit := osExitFn
	t.Cleanup(func() { osExitFn = oldExit })
	osExitFn = func(code int) {}

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = true

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExec_ExecFnError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("K", "v")

	c := config.DefaultConfig()
	withTestConfig(t, c)

	oldExec := execRunFn
	t.Cleanup(func() { execRunFn = oldExec })
	execRunFn = func(name string, args []string, env map[string]string, extra ...string) (int, error) {
		return 0, fmt.Errorf("exec failed")
	}

	oldConfirm := skipConfirm
	t.Cleanup(func() { skipConfirm = oldConfirm })
	skipConfirm = true

	cmd := &cobra.Command{}
	cmd.Flags().Bool("redact", false, "")

	err := runExec(cmd, []string{"bad-cmd"})
	if err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Errorf("expected 'exec failed' error, got: %v", err)
	}
}

// --- exec "no secrets will be injected" warning after filtering ---

func TestRunExec_NoSecretsAfterFilter(t *testing.T) {
	store, _ := newTestStore()
	store.Set("SECRET_A", "val_a")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldExcept := exceptSecrets
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		exceptSecrets = oldExcept
		authMethod = oldMethod
	})

	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"
	exceptSecrets = "SECRET_A" // exclude all secrets

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	stderr := captureStderr(t, func() {
		err := runExec(cmd, []string{"echo"})
		if err != nil {
			t.Fatalf("runExec: %v", err)
		}
	})
	if !strings.Contains(stderr, "no secrets will be injected") {
		t.Errorf("stderr = %q, want 'no secrets will be injected'", stderr)
	}
}

// --- exec "none" auth GetAll error ---

func TestRunExec_NoneAuthGetAllError(t *testing.T) {
	// Use errorKeysRing so GetAll (which calls Keys()) fails
	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorKeysRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil {
		t.Fatal("expected error when GetAll fails")
	}
	if !strings.Contains(err.Error(), "keys failed") {
		t.Errorf("error = %v, want 'keys failed'", err)
	}
}

// --- exec "oauth" auth GetAll error ---

func TestRunExec_OAuthAuthGetAllError(t *testing.T) {
	// Need a ring that supports Get (for OAuth token) but fails on Keys (for GetAll)
	ring := newMockRing()
	// Store a valid (non-expired) OAuth token so validateOAuthToken succeeds
	tokenData := `{"access_token":"tok","token_type":"bearer","expiry":"2099-01-01T00:00:00Z"}`
	ring.items["__nokey_oauth_token_github__"] = kring.Item{
		Key:  "__nokey_oauth_token_github__",
		Data: []byte(tokenData),
	}
	store := nkeyring.NewWithRing(&errorKeysRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "oauth"
	withTestConfig(t, c)

	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
	skipConfirm = true
	authMethod = "oauth"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil {
		t.Fatal("expected error when GetAll fails after OAuth")
	}
	if !strings.Contains(err.Error(), "keys failed") {
		t.Errorf("error = %v, want 'keys failed'", err)
	}
}

// --- exec GetAll error with export (for export.go coverage) ---

func TestRunExec_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}

	c := config.DefaultConfig()
	withTestConfig(t, c)

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

// --- exec "both" auth mode, OAuth fails ---

func TestRunExec_BothAuthOAuthFails(t *testing.T) {
	// "both" mode requires OAuth + PIN; with no OAuth token, validateOAuthToken fails
	store, _ := newTestStore()
	store.Set("SECRET", "val")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "both"
	withTestConfig(t, c)

	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
	skipConfirm = true
	authMethod = "both"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo"})
	if err == nil {
		t.Fatal("expected error when OAuth fails in 'both' mode")
	}
	if !strings.Contains(err.Error(), "OAuth authentication failed") {
		t.Errorf("error = %v, want 'OAuth authentication failed'", err)
	}
}

// --- exec user declines secret injection ---

func TestRunExec_UserDeclines(t *testing.T) {
	store, _ := newTestStore()
	store.Set("KEY", "val")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 0, nil
	}
	skipConfirm = false
	authMethod = "none"

	// Provide "n" as stdin to decline
	withStdin(t, "n\n")

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	_ = captureStderr(t, func() {
		err := runExec(cmd, []string{"echo"})
		if err == nil || !strings.Contains(err.Error(), "aborted") {
			t.Errorf("expected 'aborted' error, got: %v", err)
		}
	})
}

// --- exec with audit record failure (non-fatal warning) ---

func TestRunExec_AuditRecordWarning(t *testing.T) {
	// Use errorSetRing so audit.Record (which calls store.Set) fails
	ring := newMockRing()
	ring.items["KEY"] = kring.Item{Key: "KEY", Data: []byte("val")}
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestAuditDir(t)

	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "none"
	c.Audit.Enabled = true
	withTestConfig(t, c)

	oldExec := execRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
	osExitFn = func(_ int) {}
	execRunFn = func(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	stderr := captureStderr(t, func() {
		err := runExec(cmd, []string{"echo"})
		if err != nil {
			t.Fatalf("runExec should succeed despite audit error: %v", err)
		}
	})
	if !strings.Contains(stderr, "failed to record audit") {
		t.Errorf("stderr = %q, want 'failed to record audit' warning", stderr)
	}
}
