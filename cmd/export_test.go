package cmd

import (
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
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
