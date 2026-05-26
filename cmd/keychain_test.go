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
	oldOut, oldBPin := backupOut, backupPasswordIn
	oldIn, oldRPin, oldDry := restoreIn, restorePasswordIn, restoreDryRun
	oldPrompt := promptPasswordFn
	oldStdin := readPasswordStdinFn
	oldLoad := loadAllSecretsFn
	oldNoBak, oldYes := toDedicatedNoBackup, toDedicatedYes
	oldOpen := openKeyringForFn
	oldApply := applyKeychainSettingsFn
	t.Cleanup(func() {
		backupOut, backupPasswordIn = oldOut, oldBPin
		restoreIn, restorePasswordIn, restoreDryRun = oldIn, oldRPin, oldDry
		promptPasswordFn = oldPrompt
		readPasswordStdinFn = oldStdin
		loadAllSecretsFn = oldLoad
		toDedicatedNoBackup, toDedicatedYes = oldNoBak, oldYes
		openKeyringForFn = oldOpen
		applyKeychainSettingsFn = oldApply
	})
	backupOut, backupPasswordIn = "", false
	restoreIn, restorePasswordIn, restoreDryRun = "", false, false
	toDedicatedNoBackup, toDedicatedYes = false, false
	// Default tests to a deterministic password prompt so no test accidentally
	// blocks on real TTY input.
	promptPasswordFn = func(prompt string) (string, error) { return "test-pw", nil }
	readPasswordStdinFn = func() (string, error) { return "test-pw", nil }
	// Default to a no-op so tests don't shell out to `security`.
	applyKeychainSettingsFn = func(string) error { return nil }
}

// withTwoStoreOpener installs openKeyringForFn so that dedicated=false
// returns src and dedicated=true returns dst.
func withTwoStoreOpener(t *testing.T, src, dst *nkeyring.Store) {
	t.Helper()
	openKeyringForFn = func(dedicated bool) (*nkeyring.Store, error) {
		if dedicated {
			return dst, nil
		}
		return src, nil
	}
}

func dedicatedTrue() *bool { b := true; return &b }

// withDedicatedConfig sets up an isolated config dir with a saved
// config.yaml that enables keyring.dedicated. Needed because the cobra
// OnInitialize re-runs config.Load() between SetArgs and RunE, which
// would otherwise wipe an in-memory cfg mutation.
func withDedicatedConfig(t *testing.T) {
	t.Helper()
	c := config.DefaultConfig()
	c.Keyring.Dedicated = dedicatedTrue()
	withTestConfig(t, c)
	if err := config.Save(c); err != nil {
		t.Fatalf("save config: %v", err)
	}
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
	promptPasswordFn = func(string) (string, error) { return "round-trip-pw", nil }

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut})
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
	out = captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn})
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
	promptPasswordFn = func(string) (string, error) { return "pw", nil }

	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	dst, dstRing := newTestStore()
	withTestKeyring(t, dst)

	restoreIn = backupOut
	restoreDryRun = true

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn, "--dry-run"})
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
	promptPasswordFn = func(string) (string, error) { return "pw", nil }
	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Destination already has CONFLICT with a different value.
	dst, dstRing := newTestStore()
	dst.Set("CONFLICT", "different-value")
	withTestKeyring(t, dst)

	restoreIn = backupOut
	rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn})
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
	promptPasswordFn = func(string) (string, error) { return "real-pw", nil }
	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	dst, _ := newTestStore()
	withTestKeyring(t, dst)

	restoreIn = backupOut
	promptPasswordFn = func(string) (string, error) { return "wrong-pw", nil }
	rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected restore to fail with wrong password")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestKeychainBackup_PasswordStdin(t *testing.T) {
	src, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)

	src.Set("A", "1")

	dir := t.TempDir()
	backupOut = filepath.Join(dir, "snap.enc")
	backupPasswordIn = true
	// Both backup and restore go through the stdin reader when
	// --password-stdin is set; tests must not hit the real prompt.
	readPasswordStdinFn = func() (string, error) { return "stdin-pw", nil }
	// Sanity: this must NEVER be called when --password-stdin is set; if it
	// does, the test fails loudly.
	promptPasswordFn = func(string) (string, error) {
		t.Fatal("prompt should not be called when --password-stdin is set")
		return "", nil
	}

	rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut, "--password-stdin"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Decrypt via the same stdin password — restore should succeed.
	dst, _ := newTestStore()
	withTestKeyring(t, dst)
	restoreIn = backupOut
	restorePasswordIn = true
	rootCmd.SetArgs([]string{"keychain", "restore", "--in", restoreIn, "--password-stdin"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, _ := dst.Get("A"); got != "1" {
		t.Errorf("restored value = %q, want %q", got, "1")
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
	promptPasswordFn = func(string) (string, error) { return "pw", nil }
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "backup", "--out", backupOut})
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

// --- to-dedicated ---

func TestKeychainToDedicated_RefusesWhenConfigDisabled(t *testing.T) {
	src, _ := newTestStore()
	dst, _ := newTestStore()
	withTestKeyring(t, src)
	c := config.DefaultConfig()
	withTestConfig(t, c)
	withTestBackupGlobals(t)
	withTwoStoreOpener(t, src, dst)

	toDedicatedYes = true
	rootCmd.SetArgs([]string{"keychain", "to-dedicated", "--yes"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when dedicated not enabled")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "dedicated: true") {
		t.Errorf("error should show config snippet, got: %v", err)
	}
}

func TestKeychainToDedicated_RefusesOnConflict(t *testing.T) {
	src, _ := newTestStore()
	dst, dstRing := newTestStore()
	src.Set("OK", "good")
	src.Set("CONFLICT", "source-value")
	dst.Set("CONFLICT", "dest-value")

	withTestKeyring(t, src)
	withDedicatedConfig(t)
	withTestBackupGlobals(t)
	withTwoStoreOpener(t, src, dst)

	toDedicatedYes = true
	toDedicatedNoBackup = true
	rootCmd.SetArgs([]string{"keychain", "to-dedicated", "--yes", "--no-backup"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error on conflict")
	}
	if !strings.Contains(err.Error(), "CONFLICT") {
		t.Errorf("error should name conflicting key: %v", err)
	}
	if _, ok := dstRing.items["OK"]; ok {
		t.Error("OK was written despite conflict")
	}
	if string(dstRing.items["CONFLICT"].Data) != "dest-value" {
		t.Errorf("CONFLICT changed to %q", dstRing.items["CONFLICT"].Data)
	}
}

func TestKeychainToDedicated_Success(t *testing.T) {
	src, _ := newTestStore()
	dst, dstRing := newTestStore()
	src.Set("A", "1")
	src.Set("B", "2")
	src.Set("C", "3")

	withTestKeyring(t, src)
	withDedicatedConfig(t)
	withTestBackupGlobals(t)
	withTwoStoreOpener(t, src, dst)

	toDedicatedYes = true
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "to-dedicated", "--yes"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("to-dedicated: %v", err)
		}
	})
	if !strings.Contains(out, "Migrated 3") {
		t.Errorf("expected migration result, got: %s", out)
	}
	if !strings.Contains(out, "Backup:") {
		t.Errorf("expected backup line, got: %s", out)
	}
	for _, k := range []string{"A", "B", "C"} {
		v, err := dst.Get(k)
		if err != nil {
			t.Fatalf("dst.Get(%s): %v", k, err)
		}
		want, _ := src.Get(k)
		if v != want {
			t.Errorf("%s: got %q, want %q", k, v, want)
		}
	}
	if !dst.IsMigratedToDedicated() {
		t.Error("sentinel not written")
	}
	if len(dstRing.items) != 4 {
		t.Errorf("dst has %d items, want 4 (3 secrets + sentinel)", len(dstRing.items))
	}
	cd, _ := config.ConfigDir()
	entries, err := os.ReadDir(filepath.Join(cd, "backups"))
	if err != nil {
		t.Fatalf("read backups dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected at least one backup file")
	}
}

func TestKeychainToDedicated_NoBackup(t *testing.T) {
	src, _ := newTestStore()
	dst, _ := newTestStore()
	src.Set("X", "y")
	withTestKeyring(t, src)
	withDedicatedConfig(t)
	withTestBackupGlobals(t)
	withTwoStoreOpener(t, src, dst)

	toDedicatedYes = true
	toDedicatedNoBackup = true
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "to-dedicated", "--yes", "--no-backup"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("to-dedicated --no-backup: %v", err)
		}
	})
	if !strings.Contains(out, "Backup: skipped") {
		t.Errorf("expected 'Backup: skipped', got: %s", out)
	}
	cd, _ := config.ConfigDir()
	if _, err := os.Stat(filepath.Join(cd, "backups")); !os.IsNotExist(err) {
		t.Errorf("backups dir should not exist with --no-backup, stat err: %v", err)
	}
}

func TestKeychainToDedicated_Idempotent(t *testing.T) {
	src, _ := newTestStore()
	dst, _ := newTestStore()
	src.Set("A", "1")
	src.Set("B", "2")

	withTestKeyring(t, src)
	withDedicatedConfig(t)
	withTestBackupGlobals(t)
	withTwoStoreOpener(t, src, dst)

	toDedicatedYes = true
	toDedicatedNoBackup = true

	rootCmd.SetArgs([]string{"keychain", "to-dedicated", "--yes", "--no-backup"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("first run: %v", err)
	}

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "to-dedicated", "--yes", "--no-backup"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("second run: %v", err)
		}
	})
	if !strings.Contains(out, "Migrated 0") {
		t.Errorf("idempotent re-run should report 0 migrated, got: %s", out)
	}
	if !strings.Contains(out, "2 already present") {
		t.Errorf("expected 'already present' count, got: %s", out)
	}
}

// --- from-dedicated ---

// withFromDedicatedGlobals scrubs the from-dedicated/prune-orphan flag
// and stash-deletion globals between tests.
func withFromDedicatedGlobals(t *testing.T) {
	t.Helper()
	oldYes := fromDedicatedYes
	oldDry := pruneOrphanDryRun
	oldDel := deleteOrphanStashFn
	oldExists := fileExistsFn
	t.Cleanup(func() {
		fromDedicatedYes = oldYes
		pruneOrphanDryRun = oldDry
		deleteOrphanStashFn = oldDel
		fileExistsFn = oldExists
	})
	fromDedicatedYes = false
	pruneOrphanDryRun = false
	// Default both to no-ops so tests don't shell out or touch the real FS.
	deleteOrphanStashFn = func() error { return nil }
	fileExistsFn = func(string) bool { return false }
}

func TestKeychainFromDedicated_RefusesWithoutSentinel(t *testing.T) {
	src, _ := newTestStore()
	dst, _ := newTestStore() // login
	withTestKeyring(t, dst)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	// In from-dedicated, the dedicated store is the SOURCE — open it
	// where dedicated=true. Provide an empty dedicated store, no sentinel.
	withTwoStoreOpener(t, dst, src) // login=dst, dedicated=src (empty)

	fromDedicatedYes = true
	rootCmd.SetArgs([]string{"keychain", "from-dedicated", "--yes"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when sentinel absent")
	}
	if !strings.Contains(err.Error(), "no migration sentinel") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestKeychainFromDedicated_ReversesToDedicated(t *testing.T) {
	login, _ := newTestStore()
	dedicated, _ := newTestStore()
	// Simulate post-to-dedicated state: dedicated holds the secrets + sentinel.
	dedicated.Set("A", "1")
	dedicated.Set("B", "2")
	if err := dedicated.SetMigratedToDedicated(); err != nil {
		t.Fatal(err)
	}

	withTestKeyring(t, login)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	withTwoStoreOpener(t, login, dedicated)

	stashDeleted := false
	deleteOrphanStashFn = func() error { stashDeleted = true; return nil }

	fromDedicatedYes = true
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "from-dedicated", "--yes"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("from-dedicated: %v", err)
		}
	})
	if !strings.Contains(out, "Rolled back 2") {
		t.Errorf("unexpected output: %s", out)
	}
	for _, k := range []string{"A", "B"} {
		v, err := login.Get(k)
		if err != nil {
			t.Fatalf("login.Get(%s): %v", k, err)
		}
		want, _ := dedicated.Get(k)
		if v != want {
			t.Errorf("%s: got %q want %q", k, v, want)
		}
	}
	if dedicated.IsMigratedToDedicated() {
		t.Error("sentinel should have been cleared")
	}
	if !stashDeleted {
		t.Error("deleteOrphanStashFn was not called")
	}
}

func TestKeychainFromDedicated_RefusesOnConflict(t *testing.T) {
	login, loginRing := newTestStore()
	dedicated, _ := newTestStore()
	dedicated.Set("OK", "ok")
	dedicated.Set("CONFLICT", "from-dedicated")
	dedicated.SetMigratedToDedicated()
	login.Set("CONFLICT", "stale-in-login")

	withTestKeyring(t, login)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	withTwoStoreOpener(t, login, dedicated)

	fromDedicatedYes = true
	rootCmd.SetArgs([]string{"keychain", "from-dedicated", "--yes"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error on conflict")
	}
	if !strings.Contains(err.Error(), "CONFLICT") {
		t.Errorf("error should name conflict: %v", err)
	}
	if _, ok := loginRing.items["OK"]; ok {
		t.Error("OK was written despite conflict in batch")
	}
}

// --- prune-orphan ---

func TestKeychainPruneOrphan_NoStash(t *testing.T) {
	src, _ := newTestStore() // empty login keychain
	dst, _ := newTestStore()
	withTestKeyring(t, src)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	withTwoStoreOpener(t, src, dst)
	withKeychainGOOS(t, "darwin")

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "prune-orphan"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("prune-orphan: %v", err)
		}
	})
	if !strings.Contains(out, "No orphan") {
		t.Errorf("expected 'No orphan' message, got: %s", out)
	}
}

func TestKeychainPruneOrphan_DetectsAndDeletes(t *testing.T) {
	login, _ := newTestStore()
	// Inject the stash entry as if byteness/keyring had stored it.
	if err := login.Set("com.nokey.biometrics", "stash-passphrase"); err != nil {
		t.Fatal(err)
	}
	dedicated, _ := newTestStore()

	withTestKeyring(t, login)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	withTwoStoreOpener(t, login, dedicated)
	withKeychainGOOS(t, "darwin")
	// fileExistsFn defaults to false (set in withFromDedicatedGlobals),
	// simulating a missing dedicated keychain file → stash is orphaned.

	deleted := false
	deleteOrphanStashFn = func() error { deleted = true; return nil }

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "prune-orphan"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("prune-orphan: %v", err)
		}
	})
	if !strings.Contains(out, "Deleted orphan") {
		t.Errorf("expected 'Deleted orphan', got: %s", out)
	}
	if !deleted {
		t.Error("deleteOrphanStashFn was not invoked")
	}
}

func TestKeychainPruneOrphan_DryRunDoesNotDelete(t *testing.T) {
	login, _ := newTestStore()
	login.Set("com.nokey.biometrics", "stash")
	dedicated, _ := newTestStore()

	withTestKeyring(t, login)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	withTwoStoreOpener(t, login, dedicated)
	withKeychainGOOS(t, "darwin")

	deleted := false
	deleteOrphanStashFn = func() error { deleted = true; return nil }
	pruneOrphanDryRun = true

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "prune-orphan", "--dry-run"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("prune-orphan --dry-run: %v", err)
		}
	})
	if !strings.Contains(out, "Dry-run") {
		t.Errorf("expected dry-run output, got: %s", out)
	}
	if deleted {
		t.Error("dry-run should not have called deleteOrphanStashFn")
	}
}

func TestKeychainPruneOrphan_NotOrphanWhenKeychainExists(t *testing.T) {
	login, _ := newTestStore()
	login.Set("com.nokey.biometrics", "stash")
	dedicated, _ := newTestStore()

	withTestKeyring(t, login)
	withTestConfig(t, config.DefaultConfig())
	withTestBackupGlobals(t)
	withFromDedicatedGlobals(t)
	withTwoStoreOpener(t, login, dedicated)
	withKeychainGOOS(t, "darwin")
	fileExistsFn = func(string) bool { return true } // dedicated file still on disk

	deleted := false
	deleteOrphanStashFn = func() error { deleted = true; return nil }

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"keychain", "prune-orphan"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("prune-orphan: %v", err)
		}
	})
	if !strings.Contains(out, "no action needed") {
		t.Errorf("expected 'no action needed' message, got: %s", out)
	}
	if deleted {
		t.Error("should not delete stash when dedicated keychain still exists")
	}
}
