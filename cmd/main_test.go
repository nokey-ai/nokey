package cmd

import (
	"errors"
	"os"
	"testing"

	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// TestMain installs a no-op getKeyring stub before any test in this
// package runs. Any test that drives rootCmd.Execute() and reaches
// getKeyring() would otherwise touch the developer's real macOS Keychain via cgo
// SecItemCopyMatching. When the OS ACL cache has expired and the test
// has captured stdout, the cgo call sits for the Security framework
// timeout waiting for a UI dialog that nothing can acknowledge — every
// test that drives rootCmd.Execute() (TestCompletionBash, etc.) hangs.
//
// The stub returns an error, so such code paths fail before any real
// keychain access. Tests that need a working keyring continue to use
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
