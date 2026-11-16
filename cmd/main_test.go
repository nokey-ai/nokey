package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/presence"
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
//
// presenceConfirmFn is stubbed the same way, so no test shows a real
// Touch ID dialog: it reports no presence check, and tests that need one
// call withPresence.
func TestMain(m *testing.M) {
	orig := getKeyring
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, errors.New("test: no keyring installed; call withTestKeyring(t, store) if your test needs one")
	}
	origPresence := presenceConfirmFn
	presenceConfirmFn = func(context.Context, string) error {
		return fmt.Errorf("test: %w; call withPresence(t, err) if your test needs one", presence.ErrUnavailable)
	}

	code := m.Run()

	getKeyring = orig
	presenceConfirmFn = origPresence
	os.Exit(code)
}

// withPresence stands in for the person at the machine for the rest of
// the test: the presence dialog returns err (nil means confirmed) and
// records each reason it was shown.
func withPresence(t *testing.T, err error) *[]string {
	t.Helper()
	var reasons []string
	old := presenceConfirmFn
	t.Cleanup(func() { presenceConfirmFn = old })
	presenceConfirmFn = func(_ context.Context, reason string) error {
		reasons = append(reasons, reason)
		return err
	}
	return &reasons
}
