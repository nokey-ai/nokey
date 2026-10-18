package cmd

import (
	"strings"
	"testing"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
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
