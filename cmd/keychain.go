package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nokey-ai/nokey/internal/backup"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// keychainGOOS is the OS identifier used for the platform check.
// Overridable for testing.
var keychainGOOS = runtime.GOOS

var keychainCmd = &cobra.Command{
	Use:   "keychain",
	Short: "macOS Keychain management commands",
}

var keychainMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Re-create keychain items to enable Touch ID and eliminate password prompts",
	Long: `On macOS, existing keychain items may prompt for a password on every access.
This command re-creates all nokey items with updated access controls so that:
  - Touch ID can be used instead of typing a password
  - The nokey binary is added to each item's trusted-app ACL

This is only needed on macOS and only for items created before biometric
support was enabled. New items are automatically created with Touch ID access.`,
	RunE: runKeychainMigrate,
}

var (
	migrateDryRun bool
	migrateYes    bool

	backupOut        string
	backupPasswordIn bool

	restoreIn         string
	restorePasswordIn bool
	restoreDryRun     bool

	toDedicatedNoBackup bool
	toDedicatedYes      bool

	fromDedicatedYes  bool
	pruneOrphanDryRun bool
)

// deleteOrphanStashFn deletes the orphan biometrics stash entry from the
// login keychain via `security delete-generic-password`. Best-effort —
// the entry may not exist. Wrapped so tests can no-op it.
var deleteOrphanStashFn = func() error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	// -s service, -a account; matches what byteness/keyring uses for the
	// Touch ID stash.
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", "nokey", "-a", "com.nokey.biometrics")
	_ = cmd.Run() // best-effort
	return nil
}

// fileExistsFn reports whether path exists as a regular file. Wrapped so
// prune-orphan tests don't have to fabricate ~/Library/Keychains entries.
var fileExistsFn = func(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// openKeyringForFn opens either the login (dedicated=false) or dedicated
// (dedicated=true) keychain using the current config's biometrics setting
// and service name. Wrapped in a variable so the to-dedicated migration
// can be tested without two real macOS keychains.
var openKeyringForFn = func(dedicated bool) (*nkeyring.Store, error) {
	bio := cfg.Auth.UseBiometrics == nil || *cfg.Auth.UseBiometrics
	name := cfg.Keyring.Name
	if dedicated && name == "" {
		name = "nokey"
	}
	return nkeyring.New(cfg.DefaultBackend, cfg.ServiceName, bio, dedicated, name)
}

// applyKeychainSettingsFn shells out to `security set-keychain-settings`.
// Wrapped so tests can no-op it without a real keychain on disk.
var applyKeychainSettingsFn = nkeyring.ApplyKeychainSettings

// loadAllSecretsFn loads every secret from the store, gating on PIN if one
// is configured. Wrapped in a variable so tests can bypass the TTY prompt.
var loadAllSecretsFn = func(store *nkeyring.Store) (map[string]string, error) {
	if store.HasPIN() {
		return store.AuthenticatedGetAll()
	}
	return store.GetAll()
}

// promptPasswordFn reads a password from the terminal (no echo) using the
// given prompt. Overridable in tests.
var promptPasswordFn = func(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("cannot read password: stdin is not a terminal")
	}
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(pw), nil
}

// readPasswordStdinFn reads a single line from stdin and returns it as the
// password. Refuses if stdin is a terminal — --password-stdin is for piping
// (e.g. `pass show foo | nokey keychain backup ... --password-stdin`), not
// interactive entry. Overridable in tests.
var readPasswordStdinFn = func() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("--password-stdin requires a non-terminal stdin (pipe the password in)")
	}
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

var keychainBackupCmd = &cobra.Command{
	Use:   "backup --out FILE",
	Short: "Write an encrypted snapshot of every secret to FILE",
	Long: `Loads every secret (PIN-gated when a PIN is configured) and writes them
to FILE as an Argon2id + NaCl-secretbox sealed blob. You are prompted for a
passphrase on the terminal; pass --password-stdin to read it from stdin
instead (for scripting). The passphrase is never accepted as a CLI argument
because argv is visible to every other process on macOS via 'ps aux'.

The resulting file can be re-imported with 'nokey keychain restore'.`,
	RunE: runKeychainBackup,
}

var keychainFromDedicatedCmd = &cobra.Command{
	Use:   "from-dedicated",
	Short: "Roll back a to-dedicated migration: copy secrets from dedicated back to login keychain",
	Long: `Reverses 'nokey keychain to-dedicated'. Requires the migration sentinel
to be present on the dedicated keychain — refuses to run otherwise so the
command cannot quietly do nothing on a never-migrated install. Same conflict
semantics as to-dedicated: aborts atomically if any login-keychain value
differs from what is being restored.

The dedicated keychain file itself is left on disk; this command prints
the exact 'security delete-keychain' invocation if you want to remove it.`,
	RunE: runKeychainFromDedicated,
}

var keychainPruneOrphanCmd = &cobra.Command{
	Use:   "prune-orphan",
	Short: "Remove a stranded Touch ID stash from the login keychain",
	Long: `byteness/keyring stashes a passphrase under nokey/com.nokey.biometrics
in the login keychain to back the dedicated keychain's Touch ID prompt.
If the dedicated keychain file is deleted manually, that stash becomes
an orphan — this command detects and removes it.

Use --dry-run to see what would be removed without modifying anything.`,
	RunE: runKeychainPruneOrphan,
}

var keychainToDedicatedCmd = &cobra.Command{
	Use:   "to-dedicated",
	Short: "Migrate secrets from the login keychain into the configured dedicated keychain",
	Long: `Copies every secret from the macOS login keychain into the dedicated
keychain configured via keyring.dedicated/keyring.name. Requires PIN auth
(when configured) and writes an encrypted backup of every secret before
touching the destination. Migration aborts if any secret already exists in
the destination with a different value — manually resolve the conflict
(security delete-generic-password ...) and re-run. Login-keychain entries
are left in place; remove them with a future 'keychain prune-login' step.`,
	RunE: runKeychainToDedicated,
}

var keychainRestoreCmd = &cobra.Command{
	Use:   "restore --in FILE",
	Short: "Restore secrets from an encrypted backup file",
	Long: `Decrypts FILE and writes any missing secrets into the current keyring.
Secrets that already exist with the same value are skipped. Secrets that
exist with a different value cause the entire restore to abort without
writing anything, so an in-place value is never silently clobbered.

You are prompted for the passphrase on the terminal; pass --password-stdin
to read it from stdin instead. The passphrase is never accepted as a CLI
argument because argv leaks to the process table on macOS.

Use --dry-run to preview the plan without modifying the keyring.`,
	RunE: runKeychainRestore,
}

func init() {
	keychainMigrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Show what would be migrated without modifying")
	keychainMigrateCmd.Flags().BoolVar(&migrateYes, "yes", false, "Skip confirmation prompt")

	keychainBackupCmd.Flags().StringVar(&backupOut, "out", "", "Destination file path (required)")
	keychainBackupCmd.Flags().BoolVar(&backupPasswordIn, "password-stdin", false, "Read encryption password from stdin (one line) instead of prompting")
	_ = keychainBackupCmd.MarkFlagRequired("out")

	keychainRestoreCmd.Flags().StringVar(&restoreIn, "in", "", "Source backup file path (required)")
	keychainRestoreCmd.Flags().BoolVar(&restorePasswordIn, "password-stdin", false, "Read decryption password from stdin (one line) instead of prompting")
	keychainRestoreCmd.Flags().BoolVar(&restoreDryRun, "dry-run", false, "Show what would happen without modifying")
	_ = keychainRestoreCmd.MarkFlagRequired("in")

	keychainToDedicatedCmd.Flags().BoolVar(&toDedicatedNoBackup, "no-backup", false, "Skip the pre-migration encrypted backup (not recommended)")
	keychainToDedicatedCmd.Flags().BoolVar(&toDedicatedYes, "yes", false, "Skip confirmation prompt")

	keychainFromDedicatedCmd.Flags().BoolVar(&fromDedicatedYes, "yes", false, "Skip confirmation prompt")
	keychainPruneOrphanCmd.Flags().BoolVar(&pruneOrphanDryRun, "dry-run", false, "Show what would be removed without modifying")

	keychainCmd.AddCommand(keychainMigrateCmd)
	keychainCmd.AddCommand(keychainBackupCmd)
	keychainCmd.AddCommand(keychainRestoreCmd)
	keychainCmd.AddCommand(keychainToDedicatedCmd)
	keychainCmd.AddCommand(keychainFromDedicatedCmd)
	keychainCmd.AddCommand(keychainPruneOrphanCmd)
	rootCmd.AddCommand(keychainCmd)
}

// checkKeychainMigrationHint prints a one-time hint if existing items need
// migration. The hint advertises the legacy `keychain migrate` command
// (re-ACLs login-keychain items to trust the current binary). It is
// suppressed on every install where the legacy command would be the wrong
// advice: non-macOS, biometrics explicitly disabled, already migrated to
// the dedicated keychain, or running in dedicated-keychain mode at all —
// users on dedicated mode use `to-dedicated`, not the legacy migrate.
func checkKeychainMigrationHint() {
	if keychainGOOS != "darwin" {
		return
	}
	if cfg == nil || (cfg.Auth.UseBiometrics != nil && !*cfg.Auth.UseBiometrics) {
		return
	}
	if dedicatedConfigEnabled() {
		return
	}
	store, err := getKeyring()
	if err != nil {
		return
	}
	if store.IsKeychainMigrated() || store.IsMigratedToDedicated() {
		return
	}
	keys, err := store.AllKeys()
	if err != nil || len(keys) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "Hint: Run 'nokey keychain migrate' to enable Touch ID for %d existing secret(s).\n", len(keys))
}

func runKeychainMigrate(cmd *cobra.Command, args []string) error {
	if keychainGOOS != "darwin" {
		fmt.Println("Keychain migration is only needed on macOS.")
		return nil
	}

	store, err := getKeyring()
	if err != nil {
		return err
	}

	keys, err := store.AllKeys()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No keychain items to migrate.")
		return nil
	}

	if migrateDryRun {
		fmt.Printf("Would migrate %d keychain item(s):\n", len(keys))
		for _, k := range keys {
			fmt.Printf("  - %s\n", k)
		}
		return nil
	}

	if !migrateYes {
		fmt.Printf("This will re-create %d keychain item(s) with Touch ID and trusted-app ACL.\n", len(keys))
		fmt.Print("Continue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
			fmt.Println("Aborted.")
			return nil
		}
	}

	count, err := store.MigrateAllItems(false)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	if err := store.SetKeychainMigrated(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: migration succeeded but failed to write sentinel: %v\n", err)
	}

	fmt.Printf("Migrated %d keychain item(s). Touch ID is now enabled for keychain access.\n", count)
	return nil
}

// resolveBackupPassword returns the password to use for a backup or restore.
// If passwordStdin is true the password is read from stdin (for scripting);
// otherwise the user is prompted on the terminal. A passphrase is never
// accepted via a CLI flag because argv is world-readable on macOS via
// `ps aux` — the recovery passphrase must not leak to the process table.
func resolveBackupPassword(passwordStdin bool, promptText string) (string, error) {
	var (
		pw  string
		err error
	)
	if passwordStdin {
		pw, err = readPasswordStdinFn()
	} else {
		pw, err = promptPasswordFn(promptText)
	}
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return pw, nil
}

func runKeychainBackup(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	secrets, err := loadAllSecretsFn(store)
	if err != nil {
		return fmt.Errorf("load secrets: %w", err)
	}

	// Strip internal __nokey_ entries — those describe the keychain itself
	// (PIN hash, migration sentinels) and must never be replayed onto a
	// different store. The restore path would refuse them anyway.
	filtered := make(map[string]string, len(secrets))
	for k, v := range secrets {
		if strings.HasPrefix(k, "__nokey_") {
			continue
		}
		filtered[k] = v
	}

	pw, err := resolveBackupPassword(backupPasswordIn, "Backup password: ")
	if err != nil {
		return err
	}

	payload := &backup.Payload{
		Version:   backup.CurrentVersion,
		Timestamp: time.Now().UTC(),
		Secrets:   filtered,
	}
	blob, err := backup.Encrypt(payload, pw)
	if err != nil {
		return fmt.Errorf("encrypt backup: %w", err)
	}

	abs, err := filepath.Abs(backupOut)
	if err != nil {
		abs = backupOut
	}
	if err := backup.Write(abs, blob); err != nil {
		return err
	}
	fmt.Printf("Wrote %d secret(s) to %s\n", len(filtered), abs)
	return nil
}

func runKeychainRestore(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	blob, err := backup.Read(restoreIn)
	if err != nil {
		return err
	}

	pw, err := resolveBackupPassword(restorePasswordIn, "Restore password: ")
	if err != nil {
		return err
	}

	payload, err := backup.Decrypt(blob, pw)
	if err != nil {
		return err
	}
	if payload.Version != backup.CurrentVersion {
		return fmt.Errorf("backup version %d not supported (this build expects %d)", payload.Version, backup.CurrentVersion)
	}

	// Classify each secret before touching the store so we can refuse atomically.
	var toWrite, alreadyPresent, conflicts []string
	for k, v := range payload.Secrets {
		if strings.HasPrefix(k, "__nokey_") {
			// Defensive: a malicious backup must not be able to overwrite
			// the PIN hash or migration sentinels.
			continue
		}
		existing, err := store.Get(k)
		if err != nil {
			if nkeyring.IsNotFound(err) {
				toWrite = append(toWrite, k)
				continue
			}
			return fmt.Errorf("inspect %s: %w", k, err)
		}
		if existing == v {
			alreadyPresent = append(alreadyPresent, k)
		} else {
			conflicts = append(conflicts, k)
		}
	}

	if len(conflicts) > 0 {
		return fmt.Errorf("refusing to overwrite %d secret(s) with conflicting values: %s\n(delete the conflicting entries manually and re-run, or restore into a fresh keyring)",
			len(conflicts), strings.Join(conflicts, ", "))
	}

	if restoreDryRun {
		fmt.Printf("Dry-run: would write %d, already-present %d, conflicts %d\n", len(toWrite), len(alreadyPresent), len(conflicts))
		for _, k := range toWrite {
			fmt.Printf("  + %s\n", k)
		}
		return nil
	}

	for _, k := range toWrite {
		if err := store.Set(k, payload.Secrets[k]); err != nil {
			return fmt.Errorf("write %s: %w", k, err)
		}
	}
	fmt.Printf("Restored %d secret(s) (skipped %d already present)\n", len(toWrite), len(alreadyPresent))
	return nil
}

// printDedicatedSetupBannerIfFresh prints a nokey-flavored heads-up to w
// when the dedicated keychain file at path does not yet exist. The
// underlying byteness/keyring library prints its first-time setup
// prompt using a hardcoded "aws-vault" string because the library was
// originally written for that tool — this banner lets the user know
// that the misnamed prompt that follows is in fact the nokey keychain
// passphrase. The banner is suppressed when path is empty (non-macOS)
// or when the file already exists (setupTouchID will not fire again).
func printDedicatedSetupBannerIfFresh(path string, w io.Writer) {
	if path == "" {
		return
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return
	}
	fmt.Fprintln(w, `
Note: the next prompt asks for a passphrase to protect the new
nokey keychain. It says "aws-vault" because that string is hardcoded
upstream; this is the nokey dedicated keychain. One-time setup.`)
}

// dedicatedConfigEnabled reports whether the user has opted in to the
// dedicated keychain in their config. We require an explicit opt-in
// because the migration changes which file holds the user's secrets —
// flipping that silently would be a footgun.
func dedicatedConfigEnabled() bool {
	return cfg != nil && cfg.Keyring.Dedicated != nil && *cfg.Keyring.Dedicated
}

const dedicatedConfigSnippet = `keyring:
  dedicated: true
  # name: nokey   # optional; defaults to "nokey"`

func runKeychainToDedicated(cmd *cobra.Command, args []string) error {
	if !dedicatedConfigEnabled() {
		path, _ := config.ConfigPath()
		return fmt.Errorf(`dedicated keychain is not enabled in config.

Add this to %s and re-run:

%s`, path, dedicatedConfigSnippet)
	}

	if !toDedicatedYes {
		fmt.Print("This will copy every secret from your login keychain into the dedicated keychain.\nContinue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
			fmt.Println("Aborted.")
			return nil
		}
	}

	srcStore, err := openKeyringForFn(false)
	if err != nil {
		return fmt.Errorf("open login keychain: %w", err)
	}

	printDedicatedSetupBannerIfFresh(nkeyring.DedicatedKeychainPath(cfg.Keyring.Name), os.Stderr)

	dstStore, err := openKeyringForFn(true)
	if err != nil {
		return fmt.Errorf("open dedicated keychain: %w", err)
	}

	// Read source secrets first, PIN-gated. If the user can't auth here,
	// we want to fail before writing a backup file with no secrets in it.
	secrets, err := loadAllSecretsFn(srcStore)
	if err != nil {
		return fmt.Errorf("load login secrets: %w", err)
	}
	filtered := make(map[string]string, len(secrets))
	for k, v := range secrets {
		if strings.HasPrefix(k, "__nokey_") {
			continue
		}
		filtered[k] = v
	}

	// Write an encrypted backup of the source before any destination write
	// happens. The PIN doubles as the backup password — if no PIN is set,
	// prompt the user. Skipping this is opt-in only.
	backupPath := "skipped"
	if !toDedicatedNoBackup {
		pw, err := resolveBackupPassword(false, "Backup password: ")
		if err != nil {
			return err
		}
		configDir, err := config.ConfigDir()
		if err != nil {
			return fmt.Errorf("resolve config dir: %w", err)
		}
		path := backup.DefaultPath(configDir, time.Now())
		payload := &backup.Payload{
			Version:   backup.CurrentVersion,
			Timestamp: time.Now().UTC(),
			Secrets:   filtered,
		}
		blob, err := backup.Encrypt(payload, pw)
		if err != nil {
			return fmt.Errorf("encrypt backup: %w", err)
		}
		if err := backup.Write(path, blob); err != nil {
			return err
		}
		backupPath = path
	}

	// Classify against destination so we can refuse atomically on any
	// value conflict. Even one differing value aborts: silently
	// overwriting whatever the user has in the dedicated keychain
	// already would defeat the whole point of a careful migration.
	var toWrite, alreadyPresent, conflicts []string
	for k, v := range filtered {
		existing, err := dstStore.Get(k)
		if err != nil {
			if nkeyring.IsNotFound(err) {
				toWrite = append(toWrite, k)
				continue
			}
			return fmt.Errorf("inspect destination %s: %w", k, err)
		}
		if existing == v {
			alreadyPresent = append(alreadyPresent, k)
		} else {
			conflicts = append(conflicts, k)
		}
	}

	if len(conflicts) > 0 {
		dstPath := nkeyring.DedicatedKeychainPath(effectiveKeychainName())
		var lines []string
		for _, k := range conflicts {
			lines = append(lines, fmt.Sprintf("  security delete-generic-password -s %s -a %s %s", cfg.ServiceName, k, dstPath))
		}
		return fmt.Errorf("destination keychain already contains conflicting values for %d secret(s): %s\n\nDelete the conflicting entries and re-run:\n%s",
			len(conflicts), strings.Join(conflicts, ", "), strings.Join(lines, "\n"))
	}

	// Write everything new.
	for _, k := range toWrite {
		if err := dstStore.Set(k, filtered[k]); err != nil {
			return fmt.Errorf("write %s to dedicated keychain: %w", k, err)
		}
	}

	// Verify roundtrip — re-read every written secret from the destination
	// and compare against the source plaintext. If any byte differs we
	// abort BEFORE writing the sentinel so future runs treat the
	// migration as incomplete and re-attempt.
	for _, k := range toWrite {
		got, err := dstStore.Get(k)
		if err != nil {
			return fmt.Errorf("verify %s: %w", k, err)
		}
		if got != filtered[k] {
			return fmt.Errorf("verify %s: destination value differs from source", k)
		}
	}

	// Apply the lock-on-sleep / 5 min idle settings — a fresh dedicated
	// keychain has no such defaults so without this it would stay
	// unlocked forever once opened.
	if dstPath := nkeyring.DedicatedKeychainPath(effectiveKeychainName()); dstPath != "" {
		if err := applyKeychainSettingsFn(dstPath); err != nil {
			return fmt.Errorf("apply keychain settings: %w", err)
		}
	}

	if err := dstStore.SetMigratedToDedicated(); err != nil {
		return fmt.Errorf("write migration sentinel: %w", err)
	}

	fmt.Printf("Migrated %d secret(s) to the dedicated keychain (%d already present).\n", len(toWrite), len(alreadyPresent))
	fmt.Printf("Backup: %s\n", backupPath)
	fmt.Println("Login-keychain entries left in place — remove them later with 'nokey keychain prune-login' (coming in a future release).")
	return nil
}

// effectiveKeychainName returns the dedicated keychain file name the
// current config resolves to: cfg.Keyring.Name if set, otherwise "nokey".
// Centralised so the migration command and the keyring opener can't drift.
func effectiveKeychainName() string {
	if cfg != nil && cfg.Keyring.Name != "" {
		return cfg.Keyring.Name
	}
	return "nokey"
}

func runKeychainFromDedicated(cmd *cobra.Command, args []string) error {
	// Mirror to-dedicated's config gate: refuse to run unless the user has
	// explicitly enabled the dedicated keychain. The sentinel check below
	// is the real safety guard, but failing early on the config also gives
	// the user a clear error before any Touch ID prompt fires.
	if !dedicatedConfigEnabled() {
		path, _ := config.ConfigPath()
		return fmt.Errorf(`dedicated keychain is not enabled in config — nothing to roll back from.

If you previously migrated and want to roll back, add this to %s
and re-run:

%s`, path, dedicatedConfigSnippet)
	}

	srcStore, err := openKeyringForFn(true) // dedicated is the SOURCE for rollback
	if err != nil {
		return fmt.Errorf("open dedicated keychain: %w", err)
	}
	if !srcStore.IsMigratedToDedicated() {
		return fmt.Errorf("no migration sentinel found on the dedicated keychain — nothing to roll back. Run 'nokey keychain to-dedicated' first")
	}

	dstStore, err := openKeyringForFn(false) // login is the destination
	if err != nil {
		return fmt.Errorf("open login keychain: %w", err)
	}

	if !fromDedicatedYes {
		fmt.Print("This will copy every secret from the dedicated keychain back into the login keychain.\nContinue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
			fmt.Println("Aborted.")
			return nil
		}
	}

	secrets, err := loadAllSecretsFn(srcStore)
	if err != nil {
		return fmt.Errorf("load dedicated secrets: %w", err)
	}
	filtered := make(map[string]string, len(secrets))
	for k, v := range secrets {
		if strings.HasPrefix(k, "__nokey_") {
			continue
		}
		filtered[k] = v
	}

	var toWrite, alreadyPresent, conflicts []string
	for k, v := range filtered {
		existing, err := dstStore.Get(k)
		if err != nil {
			if nkeyring.IsNotFound(err) {
				toWrite = append(toWrite, k)
				continue
			}
			return fmt.Errorf("inspect login %s: %w", k, err)
		}
		if existing == v {
			alreadyPresent = append(alreadyPresent, k)
		} else {
			conflicts = append(conflicts, k)
		}
	}

	if len(conflicts) > 0 {
		return fmt.Errorf("login keychain already contains conflicting values for %d secret(s): %s\n\nDelete the conflicting login-keychain entries (security delete-generic-password -s %s -a <name>) and re-run",
			len(conflicts), strings.Join(conflicts, ", "), cfg.ServiceName)
	}

	for _, k := range toWrite {
		if err := dstStore.Set(k, filtered[k]); err != nil {
			return fmt.Errorf("write %s to login keychain: %w", k, err)
		}
	}

	// Roundtrip verify before clearing the sentinel — if any value
	// failed to land we want the migration to remain "in progress" so a
	// re-run picks up the rest.
	for _, k := range toWrite {
		got, err := dstStore.Get(k)
		if err != nil {
			return fmt.Errorf("verify %s: %w", k, err)
		}
		if got != filtered[k] {
			return fmt.Errorf("verify %s: login value differs from dedicated source", k)
		}
	}

	if err := srcStore.DeleteMigratedToDedicated(); err != nil {
		return fmt.Errorf("clear migration sentinel: %w", err)
	}

	// Drop the orphan Touch ID stash from the login keychain — once the
	// dedicated keychain is no longer in use, this entry has nothing to
	// authorise but would still survive a manual file delete and confuse
	// future runs.
	_ = deleteOrphanStashFn()

	fmt.Printf("Rolled back %d secret(s) to the login keychain (%d already present).\n", len(toWrite), len(alreadyPresent))
	if dstPath := nkeyring.DedicatedKeychainPath(effectiveKeychainName()); dstPath != "" {
		fmt.Printf("Dedicated keychain file left at %s\n", dstPath)
		fmt.Printf("Delete it manually with: security delete-keychain %s\n", dstPath)
	}
	return nil
}

func runKeychainPruneOrphan(cmd *cobra.Command, args []string) error {
	if keychainGOOS != "darwin" {
		fmt.Println("prune-orphan is only meaningful on macOS.")
		return nil
	}

	// The stash entry is stored as a login-keychain item under service
	// "nokey" and account "com.nokey.biometrics" — opening the LOGIN
	// store (dedicated=false) is how we check for it.
	loginStore, err := openKeyringForFn(false)
	if err != nil {
		return fmt.Errorf("open login keychain: %w", err)
	}

	// Use AllKeys (not List) so we can see internal-style names too.
	allKeys, err := loginStore.AllKeys()
	if err != nil {
		return fmt.Errorf("list login keychain: %w", err)
	}
	stashPresent := false
	for _, k := range allKeys {
		if k == "com.nokey.biometrics" {
			stashPresent = true
			break
		}
	}

	if !stashPresent {
		fmt.Println("No orphan Touch ID stash detected.")
		return nil
	}

	keychainFile := nkeyring.DedicatedKeychainPath(effectiveKeychainName())
	if fileExistsFn(keychainFile) {
		fmt.Printf("Touch ID stash present and dedicated keychain (%s) still exists — no action needed.\n", keychainFile)
		return nil
	}

	if pruneOrphanDryRun {
		fmt.Printf("Dry-run: would delete orphan stash (nokey:com.nokey.biometrics) from login keychain.\n")
		return nil
	}

	if err := deleteOrphanStashFn(); err != nil {
		return fmt.Errorf("delete orphan stash: %w", err)
	}
	fmt.Println("Deleted orphan Touch ID stash from login keychain.")
	return nil
}
