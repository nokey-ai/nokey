package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/spf13/cobra"
)

func TestCompletionBash(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "bash"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "bash completion") {
		t.Error("bash completion output should contain 'bash completion'")
	}
}

func TestCompletionZsh(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "zsh"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "zsh") {
		t.Error("zsh completion output should reference zsh")
	}
}

func TestCompletionFish(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "fish"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "fish") {
		t.Error("fish completion output should reference fish")
	}
}

func TestCompletionPowershell(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "powershell"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "nokey") {
		t.Error("powershell completion output should reference nokey")
	}
}

func TestCompletionInvalidShell(t *testing.T) {
	rootCmd.SetArgs([]string{"completion", "invalid"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion with invalid shell should fail")
	}
}

func TestCompletionNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"completion"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion with no args should fail")
	}
}

// completeArgs runs cobra's hidden __complete command and returns the
// suggested values (without the trailing directive line).
func completeArgs(t *testing.T, args ...string) []string {
	t.Helper()
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetArgs(nil)
	})
	rootCmd.SetArgs(append([]string{cobra.ShellCompNoDescRequestCmd}, args...))
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("__complete %v: %v", args, err)
	}

	var out []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line != "" && !strings.HasPrefix(line, ":") {
			out = append(out, line)
		}
	}
	return out
}

func TestFlagCompletions(t *testing.T) {
	tests := []struct {
		args []string
		want []string
	}{
		{[]string{"export", "--shell", ""}, []string{"bash", "zsh", "fish", "powershell"}},
		{[]string{"exec", "--auth-method", ""}, []string{"pin", "oauth", "both", "none"}},
		{[]string{"audit", "export", "--format", ""}, []string{"json", "csv"}},
		{[]string{"audit", "list", "--operation", ""}, []string{"exec", "set", "delete", "import", "export", "mcp:exec"}},
		{[]string{"audit", "export", "--operation", ""}, []string{"exec", "mcp:exec_with_secrets"}},
		{[]string{"auth", "oauth", "setup", "--provider", ""}, []string{"github", "custom"}},
		{[]string{"auth", "oauth", "refresh", "--provider", ""}, []string{"github", "custom"}},
		{[]string{"auth", "oauth", "logout", "--provider", ""}, []string{"github", "custom"}},
	}
	for _, tt := range tests {
		got := strings.Join(completeArgs(t, tt.args...), " ")
		for _, w := range tt.want {
			if !strings.Contains(" "+got+" ", " "+w+" ") {
				t.Errorf("%v: completions %q missing %q", tt.args, got, w)
			}
		}
	}
}

func TestCompletionRequest_SkipsKeyring(t *testing.T) {
	withTestConfig(t, config.DefaultConfig())
	oldGOOS := keychainGOOS
	t.Cleanup(func() { keychainGOOS = oldGOOS })
	keychainGOOS = "darwin" // the migration hint only runs on macOS

	opened := 0
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		opened++
		store, _ := newTestStore()
		return store, nil
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetArgs(nil)
	})
	for _, req := range []string{cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd} {
		rootCmd.SetArgs([]string{req, "export", "--shell", ""})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("%s: %v", req, err)
		}
	}
	if opened != 0 {
		t.Errorf("completion opened the keyring %d time(s), want 0", opened)
	}
}
