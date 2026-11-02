package cmd

import (
	"strings"
	"testing"
	"time"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/oauth"
	"github.com/nokey-ai/nokey/internal/session"
)

// runExportWith runs export for the given shell and returns stdout.
func runExportWith(t *testing.T, shell string) string {
	t.Helper()
	oldShell := shellType
	t.Cleanup(func() { shellType = oldShell })
	shellType = shell

	return captureStdout(t, func() {
		if err := runExport(nil, nil); err != nil {
			t.Fatalf("runExport: %v", err)
		}
	})
}

func TestRunExport_SortedOutput(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	names := []string{"ZETA", "ALPHA", "MIKE", "BRAVO", "YANKEE", "CHARLIE"}
	for _, n := range names {
		store.Set(n, "v")
	}

	for _, shell := range []string{"bash", "fish", "powershell"} {
		output := runExportWith(t, shell)
		lines := strings.Split(strings.TrimSpace(output), "\n")
		want := []string{"ALPHA", "BRAVO", "CHARLIE", "MIKE", "YANKEE", "ZETA"}
		if len(lines) != len(want) {
			t.Fatalf("%s: got %d lines, want %d: %q", shell, len(lines), len(want), output)
		}
		for i, name := range want {
			if !strings.Contains(lines[i], name) {
				t.Errorf("%s: line %d = %q, want %s", shell, i, lines[i], name)
			}
		}
	}
}

func TestRunExport_FishEscaping(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tests := []struct {
		value string
		want  string
	}{
		{`plain`, `set -gx K 'plain'`},
		{`ends\`, `set -gx K 'ends\\'`},
		{`a\'b`, `set -gx K 'a\\\'b'`},
		{`it's`, `set -gx K 'it\'s'`},
	}
	for _, tt := range tests {
		store.Set("K", tt.value)
		output := strings.TrimSpace(runExportWith(t, "fish"))
		if output != tt.want {
			t.Errorf("value %q: got %q, want %q", tt.value, output, tt.want)
		}
	}
}

func TestRunExport_OnlyExcept(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	store.Set("A", "1")
	store.Set("B", "2")
	store.Set("C", "3")

	oldOnly, oldExcept := exportOnly, exportExcept
	t.Cleanup(func() { exportOnly, exportExcept = oldOnly, oldExcept })

	exportOnly, exportExcept = "A, C", ""
	if got := runExportWith(t, "bash"); got != "export A='1'\nexport C='3'\n" {
		t.Errorf("--only: got %q", got)
	}

	exportOnly, exportExcept = "", "A"
	if got := runExportWith(t, "bash"); got != "export B='2'\nexport C='3'\n" {
		t.Errorf("--except: got %q", got)
	}
}

func TestRunExport_OnlyExceptErrors(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	store.Set("A", "1")

	oldOnly, oldExcept, oldShell := exportOnly, exportExcept, shellType
	t.Cleanup(func() { exportOnly, exportExcept, shellType = oldOnly, oldExcept, oldShell })
	shellType = "bash"

	tests := []struct {
		only, except, want string
	}{
		{"A", "A", "cannot use both"},
		{"MISSING", "", "secret not found: MISSING"},
	}
	for _, tt := range tests {
		exportOnly, exportExcept = tt.only, tt.except
		var err error
		output := captureStdout(t, func() { err = runExport(nil, nil) })
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("only=%q except=%q: err = %v, want %q", tt.only, tt.except, err, tt.want)
		}
		if output != "" {
			t.Errorf("only=%q except=%q: printed %q on error", tt.only, tt.except, output)
		}
	}
}

// readCountingRing records which keys were read from the backend.
type readCountingRing struct {
	*mockRing
	reads []string
}

func (r *readCountingRing) Get(key string) (kring.Item, error) {
	r.reads = append(r.reads, key)
	return r.mockRing.Get(key)
}

func TestRunExport_OnlyReadsSelectedValues(t *testing.T) {
	ring := &readCountingRing{mockRing: newMockRing()}
	for _, k := range []string{"A", "B", "C"} {
		ring.items[k] = kring.Item{Key: k, Data: []byte("v")}
	}
	withTestKeyring(t, nkeyring.NewWithRing(ring, "nokey-test"))
	withTestConfig(t, config.DefaultConfig())

	oldOnly, oldExcept := exportOnly, exportExcept
	t.Cleanup(func() { exportOnly, exportExcept = oldOnly, oldExcept })
	exportOnly, exportExcept = "B", ""

	if got := runExportWith(t, "bash"); got != "export B='v'\n" {
		t.Errorf("output = %q", got)
	}
	for _, k := range ring.reads {
		if k == "A" || k == "C" {
			t.Errorf("unselected secret %s was read from the keyring", k)
		}
	}
}

func TestRunExport_OnlyUnknownFailsBeforePIN(t *testing.T) {
	store, _ := newTestStore()
	store.SetPINHash("fakehash")
	store.Set("A", "1")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	oldOnly, oldExcept, oldShell := exportOnly, exportExcept, shellType
	t.Cleanup(func() { exportOnly, exportExcept, shellType = oldOnly, oldExcept, oldShell })
	exportOnly, exportExcept, shellType = "MISSING", "", "bash"

	err := runExport(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "secret not found: MISSING") {
		t.Errorf("err = %v, want unknown-name error before any PIN prompt", err)
	}
}

func TestRunExport_FilterLeavesNothing(t *testing.T) {
	store, _ := newTestStore()
	store.Set("A", "1")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	oldOnly, oldExcept, oldShell := exportOnly, exportExcept, shellType
	t.Cleanup(func() { exportOnly, exportExcept, shellType = oldOnly, oldExcept, oldShell })
	exportOnly, exportExcept, shellType = "", "A", "bash"

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runExport(nil, nil); err != nil {
				t.Fatalf("runExport: %v", err)
			}
		})
	})
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if !strings.Contains(stderr, "Warning: no secrets to export") || strings.Contains(stderr, "no secrets stored") {
		t.Errorf("stderr = %q, want the no-secrets-to-export warning", stderr)
	}
}

// --- export authenticates like exec ---

// exportAuthSetup prepares a store with secret A=1 under the given
// default_method. pin stores a PIN hash with a valid session, so no
// prompt is needed; token stores a valid GitHub OAuth token.
func exportAuthSetup(t *testing.T, store *nkeyring.Store, method string, pin, token bool) {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // keep the session ticket out of the real home
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.Auth.DefaultMethod = method
	c.Auth.SessionTTL = "5m"
	withTestConfig(t, c)

	store.Set("A", "1")
	if pin {
		store.SetPINHash("export-hash")
		if err := session.Create("export-hash"); err != nil {
			t.Fatalf("session.Create: %v", err)
		}
	}
	if token {
		tok := &oauth.Token{AccessToken: "valid", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
		if err := oauth.SaveToken(store, "github", tok); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}
	}

	oldOnly, oldExcept, oldShell := exportOnly, exportExcept, shellType
	t.Cleanup(func() { exportOnly, exportExcept, shellType = oldOnly, oldExcept, oldShell })
	exportOnly, exportExcept = "", ""
}

func TestRunExport_AuthMethods(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		token     bool
		wantAudit string
	}{
		{name: "none", method: "none", wantAudit: "none"},
		{name: "oauth", method: "oauth", token: true, wantAudit: "oauth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestStore()
			exportAuthSetup(t, store, tt.method, false, tt.token)

			if got := runExportWith(t, "bash"); got != "export A='1'\n" {
				t.Errorf("output = %q", got)
			}

			log, err := audit.Load(store)
			if err != nil {
				t.Fatalf("audit.Load: %v", err)
			}
			if len(log.Entries) == 0 {
				t.Fatal("no audit entry recorded")
			}
			last := log.Entries[len(log.Entries)-1]
			if last.Operation != "export" || last.AuthMethod != tt.wantAudit {
				t.Errorf("audit entry = %s/%s, want export/%s", last.Operation, last.AuthMethod, tt.wantAudit)
			}
		})
	}
}

// A stored PIN always gates export, whatever default_method says, and a
// valid PIN session never skips the prompt. The test setup creates a valid
// session; with no terminal the prompt fails, which shows it was reached.
func TestRunExport_PINAlwaysPrompts(t *testing.T) {
	tests := []struct {
		name   string
		method string
		token  bool
	}{
		{name: "pin", method: "pin"},
		{name: "both", method: "both", token: true},
		{name: "legacy stored PIN", method: ""},
		{name: "none is raised to pin", method: "none"},
		{name: "oauth is raised to both", method: "oauth", token: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestStore()
			exportAuthSetup(t, store, tt.method, true, tt.token)
			shellType = "bash"

			var err error
			output := captureStdout(t, func() { err = runExport(nil, nil) })
			if err == nil || !strings.Contains(err.Error(), "PIN authentication failed") {
				t.Errorf("err = %v, want the PIN prompt to be reached", err)
			}
			if output != "" {
				t.Errorf("printed %q without a PIN", output)
			}
		})
	}
}

func TestExportAuthMethod(t *testing.T) {
	for _, tt := range []struct{ method, withPIN, withoutPIN string }{
		{"none", "pin", "none"},
		{"pin", "pin", "pin"},
		{"oauth", "both", "oauth"},
		{"both", "both", "both"},
	} {
		noPIN, _ := newTestStore()
		if got := exportAuthMethod(noPIN, tt.method); got != tt.withoutPIN {
			t.Errorf("exportAuthMethod(no PIN, %q) = %q, want %q", tt.method, got, tt.withoutPIN)
		}
		withPIN, _ := newTestStore()
		withPIN.SetPINHash("hash")
		if got := exportAuthMethod(withPIN, tt.method); got != tt.withPIN {
			t.Errorf("exportAuthMethod(PIN, %q) = %q, want %q", tt.method, got, tt.withPIN)
		}
	}
}

func TestRunExport_AuthFailures(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		pin, token bool
		wantErr    string
	}{
		// OAuth configured without a PIN used to export unauthenticated.
		{name: "oauth without token", method: "oauth", wantErr: "OAuth authentication failed"},
		// both used to check only the PIN.
		{name: "both without token", method: "both", pin: true, wantErr: "OAuth authentication failed"},
		{name: "pin without PIN set", method: "pin", wantErr: "PIN authentication failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestStore()
			exportAuthSetup(t, store, tt.method, tt.pin, tt.token)
			shellType = "bash"

			var err error
			output := captureStdout(t, func() { err = runExport(nil, nil) })
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
			if output != "" {
				t.Errorf("printed %q despite failed authentication", output)
			}
		})
	}
}

// An unsupported shell is rejected before the keyring is opened, so the
// user isn't asked to authenticate for an export that can't succeed.
func TestRunExport_UnsupportedShellBeforeAuth(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		t.Error("keyring opened before the shell was validated")
		store, _ := newTestStore()
		return store, nil
	}
	oldShell := shellType
	t.Cleanup(func() { shellType = oldShell })
	shellType = "tcsh"

	err := runExport(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported shell type: tcsh") {
		t.Errorf("err = %v, want unsupported shell error", err)
	}
}

func TestRunExport_UnsupportedShellNoSecrets(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	oldShell := shellType
	t.Cleanup(func() { shellType = oldShell })
	shellType = "tcsh"

	if err := runExport(nil, nil); err == nil || !strings.Contains(err.Error(), "unsupported shell type") {
		t.Errorf("err = %v, want unsupported shell error with no secrets stored", err)
	}
}

func TestRunExport_PwshAlias(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	store.Set("A", "1")

	if got := runExportWith(t, "pwsh"); got != "$env:A='1'\n" {
		t.Errorf("output = %q", got)
	}
}
