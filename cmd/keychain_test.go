package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

func withKeychainGOOS(t *testing.T, goos string) {
	t.Helper()
	old := keychainGOOS
	t.Cleanup(func() { keychainGOOS = old })
	keychainGOOS = goos
}

func withMigrateFlags(t *testing.T) {
	t.Helper()
	oldDry := migrateDryRun
	oldYes := migrateYes
	t.Cleanup(func() {
		migrateDryRun = oldDry
		migrateYes = oldYes
	})
	migrateDryRun = false
	migrateYes = false
}

func TestKeychainMigrate_NonDarwin(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	withKeychainGOOS(t, "linux")
	withMigrateFlags(t)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "migrate"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "only needed on macOS") {
		t.Errorf("expected macOS-only message, got: %s", out)
	}
}

func TestKeychainMigrate_NoKeys(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	withKeychainGOOS(t, "darwin")
	withMigrateFlags(t)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "migrate"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "No keychain items") {
		t.Errorf("expected 'No keychain items' message, got: %s", out)
	}
}

func TestKeychainMigrate_DryRun(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	withKeychainGOOS(t, "darwin")
	withMigrateFlags(t)

	// Seed some keys
	store.Set("API_KEY", "val1")
	store.Set("DB_PASS", "val2")

	migrateDryRun = true

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "migrate", "--dry-run"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "Would migrate") {
		t.Errorf("expected dry-run output, got: %s", out)
	}
	if !strings.Contains(out, "API_KEY") {
		t.Errorf("expected key names in output, got: %s", out)
	}
}

func TestKeychainMigrate_YesFlag(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	withKeychainGOOS(t, "darwin")
	withMigrateFlags(t)

	store.Set("MY_SECRET", "secret")
	migrateYes = true

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "migrate", "--yes"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// MigrateAllItems returns (0, nil) on non-darwin, so count is 0
	if !strings.Contains(out, "Migrated") {
		t.Errorf("expected migration result, got: %s", out)
	}
}

func TestKeychainMigrate_InteractiveNo(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	withKeychainGOOS(t, "darwin")
	withMigrateFlags(t)

	store.Set("MY_SECRET", "secret")

	// Simulate user typing "n\n"
	withStdin(t, "n\n")

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "migrate"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "Aborted") {
		t.Errorf("expected 'Aborted' message, got: %s", out)
	}
}

func TestKeychainMigrate_GetKeyringError(t *testing.T) {
	withTestConfig(t, config.DefaultConfig())
	withKeychainGOOS(t, "darwin")
	withMigrateFlags(t)

	// Override getKeyring to return an error
	oldGetKeyring := getKeyring
	t.Cleanup(func() { getKeyring = oldGetKeyring })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring unavailable")
	}

	rootCmd.SetArgs([]string{"keychain", "migrate"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when keyring unavailable")
	}
	if !strings.Contains(err.Error(), "keyring unavailable") {
		t.Errorf("expected keyring error, got: %v", err)
	}
}
