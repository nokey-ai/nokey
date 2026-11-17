package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
)

// A program running as the user can run the CLI, so rename, delete and
// overwrite must not go through without the person at the machine.
func TestSecretChanges_NeedPresence(t *testing.T) {
	oldUseStdin := useStdin
	t.Cleanup(func() { useStdin = oldUseStdin })
	useStdin = true

	tests := []struct {
		name   string
		run    func(t *testing.T) error
		reason string
	}{
		{"rename", func(*testing.T) error { return runRename(nil, []string{"PROD_KEY", "GITHUB_X"}) }, `rename the secret "PROD_KEY" to "GITHUB_X"`},
		{"delete", func(*testing.T) error { return runDelete(nil, []string{"PROD_KEY"}) }, `delete the secret "PROD_KEY"`},
		{"set", func(t *testing.T) error {
			withStdin(t, "planted\n")
			return runSet(nil, []string{"PROD_KEY"})
		}, `replace the secret "PROD_KEY"`},
		{"import", func(t *testing.T) error {
			return runImport(nil, []string{writeEnvFile(t, "PROD_KEY=planted\nNEW_KEY=new\n")})
		}, `"PROD_KEY"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestStore()
			withTestKeyring(t, store)
			c := config.DefaultConfig()
			c.Audit.Enabled = false
			withTestConfig(t, c)
			_ = store.Set("PROD_KEY", "original")
			reasons := withPresence(t, errors.New("not confirmed: cancelled"))

			var err error
			_ = captureStdout(t, func() {
				_ = captureStderr(t, func() { err = tt.run(t) })
			})
			if err == nil || !strings.Contains(err.Error(), "not confirmed") {
				t.Errorf("error = %v, want the presence refusal", err)
			}
			if len(*reasons) != 1 || !strings.Contains((*reasons)[0], tt.reason) {
				t.Errorf("presence reasons = %q, want one containing %q", *reasons, tt.reason)
			}
			if keys, _ := store.List(); len(keys) != 1 || keys[0] != "PROD_KEY" {
				t.Errorf("keys = %v, want only PROD_KEY", keys)
			}
			if got, _ := store.Get("PROD_KEY"); got != "original" {
				t.Errorf("PROD_KEY = %q, want it unchanged", got)
			}
		})
	}
}

// Storing a secret under a new name replaces nothing, so it stays
// promptless: TestMain's presence stub would refuse a prompt.
func TestSecretChanges_NewNamesNeedNoPresence(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)
	oldUseStdin := useStdin
	t.Cleanup(func() { useStdin = oldUseStdin })
	useStdin = true
	withStdin(t, "value\n")

	_ = captureStdout(t, func() {
		if err := runSet(nil, []string{"FRESH_KEY"}); err != nil {
			t.Errorf("runSet: %v", err)
		}
		_ = captureStderr(t, func() {
			if err := runImport(nil, []string{writeEnvFile(t, "OTHER_KEY=v\n")}); err != nil {
				t.Errorf("runImport: %v", err)
			}
		})
	})
}
