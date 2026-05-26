package cmd

import (
	"errors"
	"os"
	"testing"

	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// TestMain installs a no-op getKeyring stub before any test in this
// package runs. rootCmd.PersistentPreRun (cmd/root.go:60) calls
// checkKeychainMigrationHint, which calls getKeyring(), which without
// this stub reaches the developer's real macOS Keychain via cgo
// SecItemCopyMatching. When the OS ACL cache has expired and the test
// has captured stdout, the cgo call sits for the Security framework
// timeout waiting for a UI dialog that nothing can acknowledge — every
// test that drives rootCmd.Execute() (TestCompletionBash, etc.) hangs.
//
// The stub returns an error so checkKeychainMigrationHint's
// "if err != nil { return }" guard exits before any real keychain
// access. Tests that need a working keyring continue to use
// withTestKeyring(t, store), which overrides this stub for the test's
// duration via t.Cleanup.
func TestMain(m *testing.M) {
	orig := getKeyring
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, errors.New("test: no keyring installed; call withTestKeyring(t, store) if your test needs one")
	}

	code := m.Run()

	getKeyring = orig
	os.Exit(code)
}
