package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// withTestBackupGlobals saves and restores all backup/restore flag globals
// and the password prompt hook so tests can scrub state between runs.
func withTestBackupGlobals(t *testing.T) {
	t.Helper()
	oldOut, oldBP := backupOut, backupPassword
	oldIn, oldRP, oldDry := restoreIn, restorePassword, restoreDryRun
	oldPrompt := promptPasswordFn
	oldLoad := loadAllSecretsFn
	t.Cleanup(func() {
		backupOut, backupPassword = oldOut, oldBP
		restoreIn, restorePassword, restoreDryRun = oldIn, oldRP, oldDry
		promptPasswordFn = oldPrompt
		loadAllSecretsFn = oldLoad
	})
	backupOut, backupPassword = "", ""
	restoreIn, restorePassword, restoreDryRun = "", "", false
	// Default tests to a deterministic password prompt so no test accidentally
	// blocks on real TTY input.
	promptPasswordFn = func(prompt string) (string, error) { return "test-pw", nil }
}

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

// --- backup + restore ---

func TestKeychainBackupRestore_RoundTrip(t *testing.T) {
	src, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)

	src.Set("API_KEY", "sk-test-123")
	src.Set("DB_URL", "postgres://x")
	src.Set("MULTI", "a\nb\nc")

	dir := t.TempDir()
	backupOut = filepath.Join(dir, "snap.enc")
	backupPassword = "round-trip-pw"

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut, "--password", backupPassword})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})
	if !strings.Contains(out, "Wrote 3 secret") {
		t.Errorf("unexpected backup output: %s", out)
	}

	// Swap to an empty store and restore.
	dst, _ := newTestStore()
	withTestKeyring(t, dst)

	restoreIn = backupOut
	restorePassword = "round-trip-pw"
	out = captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn, "--password", restorePassword})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("restore: %v", err)
		}
	})
	if !strings.Contains(out, "Restored 3") {
		t.Errorf("unexpected restore output: %s", out)
	}

	for _, k := range []string{"API_KEY", "DB_URL", "MULTI"} {
		got, err := dst.Get(k)
		if err != nil {
			t.Fatalf("Get(%s): %v", k, err)
		}
		want, _ := src.Get(k)
		if got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
}

func TestKeychainRestore_DryRunDoesNotWrite(t *testing.T) {
	src, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)

	src.Set("ONLY_KEY", "v")
	dir := t.TempDir()
	backupOut = filepath.Join(dir, "snap.enc")
	backupPassword = "pw"

	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut, "--password", backupPassword})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	dst, dstRing := newTestStore()
	withTestKeyring(t, dst)

	restoreIn = backupOut
	restorePassword = "pw"
	restoreDryRun = true

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn, "--password", restorePassword, "--dry-run"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("restore --dry-run: %v", err)
		}
	})
	if !strings.Contains(out, "Dry-run") {
		t.Errorf("expected dry-run output, got: %s", out)
	}
	if len(dstRing.items) != 0 {
		t.Errorf("dry-run wrote %d items, want 0", len(dstRing.items))
	}
}

func TestKeychainRestore_RefusesOnConflict(t *testing.T) {
	src, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)

	src.Set("OK", "good")
	src.Set("CONFLICT", "from-backup")
	dir := t.TempDir()
	backupOut = filepath.Join(dir, "snap.enc")
	backupPassword = "pw"
	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut, "--password", backupPassword})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Destination already has CONFLICT with a different value.
	dst, dstRing := newTestStore()
	dst.Set("CONFLICT", "different-value")
	withTestKeyring(t, dst)

	restoreIn = backupOut
	restorePassword = "pw"
	rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn, "--password", restorePassword})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected restore to fail on conflict")
	}
	if !strings.Contains(err.Error(), "CONFLICT") {
		t.Errorf("error should name conflicting key: %v", err)
	}
	// OK must not have been written — refusal is atomic.
	if _, ok := dstRing.items["OK"]; ok {
		t.Error("OK was written despite conflict in batch")
	}
	if dstRing.items["CONFLICT"].Data != nil && string(dstRing.items["CONFLICT"].Data) != "different-value" {
		t.Errorf("CONFLICT was overwritten: %q", dstRing.items["CONFLICT"].Data)
	}
}

func TestKeychainRestore_WrongPassword(t *testing.T) {
	src, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)

	src.Set("X", "y")
	dir := t.TempDir()
	backupOut = filepath.Join(dir, "snap.enc")
	backupPassword = "real-pw"
	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut, "--password", backupPassword})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	dst, _ := newTestStore()
	withTestKeyring(t, dst)

	restoreIn = backupOut
	restorePassword = "wrong-pw"
	rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn, "--password", restorePassword})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected restore to fail with wrong password")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestKeychainBackup_StripsInternalKeys(t *testing.T) {
	src, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)

	src.Set("REAL", "v")
	// Inject an internal sentinel via the public PIN-hash API.
	src.SetPINHash("fakehash")

	// Override the loader: HasPIN is true so the real path would hit a TTY
	// auth prompt — bypass it and return everything (including the sentinel)
	// so we can verify the filter happens in the backup command.
	loadAllSecretsFn = func(s *nkeyring.Store) (map[string]string, error) {
		return map[string]string{
			"REAL":               "v",
			"__nokey_pin_hash__": "fakehash",
		}, nil
	}

	dir := t.TempDir()
	backupOut = filepath.Join(dir, "snap.enc")
	backupPassword = "pw"
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut, "--password", backupPassword})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})
	if !strings.Contains(out, "Wrote 1 secret") {
		t.Errorf("expected only 1 secret written (internal stripped), got: %s", out)
	}

	stat, err := os.Stat(backupOut)
	if err != nil || stat.Size() == 0 {
		t.Fatalf("backup file: %v size=%d", err, stat.Size())
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
