package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/config"
	iexec "github.com/nokey-ai/nokey/internal/exec"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
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

// --- policy enforcement on CLI exec ---

// withTestConfigDir overrides config.ConfigDir to a temp dir and writes the
// given policies.yaml content into it (if non-empty). Returns the dir.
func withTestConfigDir(t *testing.T, policiesYAML string) string {
	t.Helper()
	dir := t.TempDir()
	old := config.ConfigDir
	t.Cleanup(func() { config.ConfigDir = old })
	config.ConfigDir = func() (string, error) { return dir, nil }
	if policiesYAML != "" {
		if err := os.WriteFile(dir+"/policies.yaml", []byte(policiesYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRunExec_PolicyDenies(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)
	withTestConfigDir(t, "approval: never\nrules:\n  - commands: [\"ls\"]\n    secrets: [\"OTHER\"]\n")
	store.Set("MY_SECRET", "v")

	withExecGlobals(t)
	osExitFn = func(_ int) {}
	execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
		t.Fatal("execRunFn should not run when policy denies")
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo", "hi"})
	if err == nil {
		t.Fatal("expected policy denial error, got nil")
	}
	if !strings.Contains(err.Error(), "policy denied") {
		t.Errorf("error = %v, want policy denial", err)
	}
}

// A token_required rule is refused by the CLI: session tokens exist only in
// the MCP server, so skipping the rule here would let an agent shell out
// around it.
func TestRunExec_PolicyTokenRequiredDenies(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)
	withTestConfigDir(t, "rules:\n  - commands: [\"echo\"]\n    secrets: [\"MY_SECRET\"]\n    approval: never\n    token_required: true\n")
	store.Set("MY_SECRET", "v")

	withExecGlobals(t)
	osExitFn = func(_ int) {}
	execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
		t.Fatal("execRunFn should not run when policy requires a token")
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"echo", "hi"})
	if err == nil || !strings.Contains(err.Error(), "requires a session token") {
		t.Fatalf("error = %v, want token-required denial", err)
	}
}

func TestRunExec_PolicyAllows(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)
	withTestConfigDir(t, "approval: never\nrules:\n  - commands: [\"echo\"]\n    secrets: [\"MY_SECRET\"]\n")
	store.Set("MY_SECRET", "v")

	withExecGlobals(t)
	osExitFn = func(_ int) {}
	called := false
	execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
		called = true
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	if err := runExec(cmd, []string{"echo", "hi"}); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !called {
		t.Error("execRunFn should run when policy allows")
	}
}

func TestRunExec_PolicyOptOut(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	off := false
	c.Auth.CLIEnforcePolicy = &off
	withTestConfig(t, c)
	// Policy would deny if enforced.
	withTestConfigDir(t, "approval: never\nrules:\n  - commands: [\"ls\"]\n    secrets: [\"OTHER\"]\n")
	store.Set("MY_SECRET", "v")

	withExecGlobals(t)
	osExitFn = func(_ int) {}
	called := false
	execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
		called = true
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	if err := runExec(cmd, []string{"echo", "hi"}); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !called {
		t.Error("execRunFn should run when cli_enforce_policy=false bypasses denial")
	}
}

func TestRunExec_NoPolicyFileAllows(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	withTestConfig(t, c)
	// No policies.yaml written → allow-all.
	withTestConfigDir(t, "")
	store.Set("MY_SECRET", "v")

	withExecGlobals(t)
	osExitFn = func(_ int) {}
	called := false
	execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
		called = true
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	if err := runExec(cmd, []string{"echo", "hi"}); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !called {
		t.Error("execRunFn should run when no policies.yaml exists (allow-all)")
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

// A config or flag naming a removed auth method fails with an error that
// says so, rather than falling back to a weaker method.
func TestRunExec_RemovedAuthMethods(t *testing.T) {
	for _, tc := range []struct{ configured, flag, want string }{
		{"oauth", "", "auth method 'oauth' in config was removed in nokey v0.9.0"},
		{"both", "", "auth method 'both' in config was removed in nokey v0.9.0"},
		{"none", "oauth", "auth method 'oauth' was removed in nokey v0.9.0"},
		{"pin", "both", "auth method 'both' was removed in nokey v0.9.0"},
	} {
		t.Run(tc.configured+"/"+tc.flag, func(t *testing.T) {
			store, _ := newTestStore()
			store.Set("KEY", "val")
			withTestKeyring(t, store)
			c := config.DefaultConfig()
			c.Auth.DefaultMethod = tc.configured
			withTestConfig(t, c)

			withExecGlobals(t)
			execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
				t.Error("command must not run with a removed auth method")
				return 0, nil
			}
			authMethod = tc.flag

			cmd := &cobra.Command{}
			cmd.Flags().BoolVar(&enableRedact, "redact", false, "")
			err := runExec(cmd, []string{"echo"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
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

// The isolation proxy records blocked requests in the audit log, like
// nokey proxy start does.
func TestSetupIsolationProxy_AuditsBlockedRequests(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)
	withTestConfigDir(t, `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_KEY"
`)

	envVars, cleanup, err := setupIsolationProxy(map[string]string{"MY_KEY": "secret-val"})
	if err != nil {
		t.Fatalf("setupIsolationProxy: %v", err)
	}
	defer cleanup()

	var proxyURL string
	for _, ev := range envVars {
		if strings.HasPrefix(ev, "http_proxy=") {
			proxyURL = strings.TrimPrefix(ev, "http_proxy=")
		}
	}
	if proxyURL == "" {
		t.Fatalf("no http_proxy in %v", envVars)
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := client.Get("http://blocked.example/")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	log, err := audit.Load(store)
	if err != nil {
		t.Fatalf("audit.Load: %v", err)
	}
	for _, e := range log.Entries {
		if e.Operation == "proxy:http:blocked" {
			return
		}
	}
	t.Errorf("no proxy:http:blocked audit entry; entries: %+v", log.Entries)
}

func TestSetupIsolationProxy_OverridesProxyBypassVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX env command")
	}
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)
	// An inherited NO_PROXY=* would let the child skip the isolation proxy
	// entirely, and ALL_PROXY would route non-HTTP clients elsewhere.
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("all_proxy", "socks5://127.0.0.1:1")

	configDir := fmt.Sprintf("%s/.config/nokey", dir)
	os.MkdirAll(configDir, 0700)
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_KEY"
`
	os.WriteFile(configDir+"/policies.yaml", []byte(polYAML), 0600)

	envVars, cleanup, err := setupIsolationProxy(map[string]string{"MY_KEY": "secret-val"})
	if err != nil {
		t.Fatalf("setupIsolationProxy: %v", err)
	}
	defer cleanup()

	// Run a real child through the same env merge nokey exec uses, and
	// read back the environment it actually received.
	out, err := os.CreateTemp(t.TempDir(), "env")
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = out
	code, runErr := iexec.Run("env", nil, nil, envVars...)
	os.Stdout = oldStdout
	if runErr != nil || code != 0 {
		t.Fatalf("running env: code=%d err=%v", code, runErr)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v
		}
	}
	var proxyURL string
	for _, ev := range envVars {
		if v, ok := strings.CutPrefix(ev, "http_proxy="); ok {
			proxyURL = v
		}
	}
	if proxyURL == "" {
		t.Fatalf("expected http_proxy in env vars, got: %v", envVars)
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if got[k] != "" {
			t.Errorf("%s = %q, want empty", k, got[k])
		}
	}
	for _, k := range []string{"ALL_PROXY", "all_proxy"} {
		if got[k] != proxyURL {
			t.Errorf("%s = %q, want %q", k, got[k], proxyURL)
		}
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

// TestRunExec_CleansUpBeforeExit verifies that the secrets map is wiped and
// the isolation proxy stopped before runExec exits with the child's code.
// os.Exit skips deferred calls, so cleanup left to defers never runs.
func TestRunExec_CleansUpBeforeExit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("MY_KEY", "secret-val")

	c := config.DefaultConfig()
	c.Audit.Enabled = false
	c.Auth.DefaultMethod = "none"
	enforce := false
	c.Auth.CLIEnforcePolicy = &enforce
	withTestConfig(t, c)

	configDir, err := getConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_KEY"
`
	if err := os.WriteFile(configDir+"/policies.yaml", []byte(polYAML), 0600); err != nil {
		t.Fatal(err)
	}

	withExecGlobals(t)
	oldIsolate := enableIsolate
	t.Cleanup(func() { enableIsolate = oldIsolate })
	enableIsolate = true

	var injected map[string]string
	var proxyAddr string
	execRunFn = func(_ string, _ []string, secrets map[string]string, extraEnv ...string) (int, error) {
		injected = secrets
		for _, ev := range extraEnv {
			if v, ok := strings.CutPrefix(ev, "http_proxy=http://"); ok {
				proxyAddr = v
			}
		}
		return 3, nil
	}
	exited := false
	osExitFn = func(code int) {
		exited = true
		if code != 3 {
			t.Errorf("exit code = %d, want 3", code)
		}
		if len(injected) != 0 {
			t.Error("secrets map not cleared before exit")
		}
		if conn, err := net.DialTimeout("tcp", proxyAddr, time.Second); err == nil {
			_ = conn.Close()
			t.Error("isolation proxy still listening at exit")
		}
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")
	if err := runExec(cmd, []string{"echo"}); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if !exited {
		t.Fatal("expected runExec to exit with the child's code")
	}
	if proxyAddr == "" {
		t.Fatal("expected the isolation proxy address in the child env")
	}
}

// --- --auth-method can only strengthen the configured method ---

func TestResolveAuthMethod(t *testing.T) {
	tests := []struct {
		configured string // auth.default_method
		hasPIN     bool   // legacy: a PIN set with no default_method
		override   string
		want       string
		wantErr    string // non-empty = error expected
	}{
		// No override: the configured method is used as-is.
		{configured: "pin", want: "pin"},
		{configured: "", want: "none"},
		{configured: "", hasPIN: true, want: "pin"},

		// Equal or stronger overrides are allowed.
		{configured: "none", override: "none", want: "none"},
		{configured: "none", override: "pin", want: "pin"},
		{configured: "pin", override: "pin", want: "pin"},
		{configured: "", hasPIN: true, override: "pin", want: "pin"},

		// A downgrade is refused.
		{configured: "pin", override: "none", wantErr: "--auth-method none would skip pin required by config"},
		{configured: "", hasPIN: true, override: "none", wantErr: "--auth-method none would skip pin required by config"},

		// Unknown and removed methods are rejected, with or without a flag.
		{configured: "none", override: "bogus", wantErr: "invalid auth method 'bogus'"},
		{configured: "bogus", wantErr: "invalid auth method 'bogus' in config"},
		{configured: "bogus", override: "pin", wantErr: "invalid auth method 'bogus' in config"},
		{configured: "oauth", wantErr: "auth method 'oauth' in config was removed in nokey v0.9.0"},
		{configured: "both", override: "pin", wantErr: "auth method 'both' in config was removed in nokey v0.9.0"},
		{configured: "none", override: "oauth", wantErr: "auth method 'oauth' was removed in nokey v0.9.0"},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("config=%q pin=%v flag=%q", tt.configured, tt.hasPIN, tt.override)
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore()
			if tt.hasPIN {
				store.SetPINHash("hash")
			}
			c := config.DefaultConfig()
			c.Auth.DefaultMethod = tt.configured
			withTestConfig(t, c)

			got, err := resolveAuthMethod(store, tt.override)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got (%q, %v), want error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// The legacy require_auth setting counts as configuring pin.
func TestResolveAuthMethod_LegacyRequireAuth(t *testing.T) {
	store, _ := newTestStore()
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = ""
	c.RequireAuth = true
	withTestConfig(t, c)

	if _, err := resolveAuthMethod(store, "none"); err == nil || !strings.Contains(err.Error(), "would skip pin") {
		t.Fatalf("expected downgrade error, got %v", err)
	}
}

// A downgrade via the flag fails before any secret is read or the command runs.
func TestRunExec_AuthMethodDowngradeRefused(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = ""
	withTestConfig(t, c)
	store.Set("KEY", "val")
	store.SetPINHash("hash")

	withExecGlobals(t)
	execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
		t.Error("command must not run when --auth-method downgrades auth")
		return 0, nil
	}
	skipConfirm = true
	authMethod = "none"

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableRedact, "redact", false, "")

	err := runExec(cmd, []string{"printenv"})
	if err == nil || !strings.Contains(err.Error(), "--auth-method none would skip pin required by config") {
		t.Fatalf("expected downgrade error, got: %v", err)
	}
}
