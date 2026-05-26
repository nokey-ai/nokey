package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nokey-ai/nokey/internal/backup"
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

	backupOut      string
	backupPassword string

	restoreIn       string
	restorePassword string
	restoreDryRun   bool
)

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

var keychainBackupCmd = &cobra.Command{
	Use:   "backup --out FILE",
	Short: "Write an encrypted snapshot of every secret to FILE",
	Long: `Loads every secret (PIN-gated when a PIN is configured) and writes them
to FILE as an Argon2id + NaCl-secretbox sealed blob. The password defaults to
the PIN; with no PIN, you are prompted for a one-shot passphrase.

The resulting file can be re-imported with 'nokey keychain restore'.`,
	RunE: runKeychainBackup,
}

var keychainRestoreCmd = &cobra.Command{
	Use:   "restore --in FILE",
	Short: "Restore secrets from an encrypted backup file",
	Long: `Decrypts FILE and writes any missing secrets into the current keyring.
Secrets that already exist with the same value are skipped. Secrets that
exist with a different value cause the entire restore to abort without
writing anything, so an in-place value is never silently clobbered.

Use --dry-run to preview the plan without modifying the keyring.`,
	RunE: runKeychainRestore,
}

func init() {
	keychainMigrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Show what would be migrated without modifying")
	keychainMigrateCmd.Flags().BoolVar(&migrateYes, "yes", false, "Skip confirmation prompt")

	keychainBackupCmd.Flags().StringVar(&backupOut, "out", "", "Destination file path (required)")
	keychainBackupCmd.Flags().StringVar(&backupPassword, "password", "", "Encryption password (default: PIN, else prompt)")
	_ = keychainBackupCmd.MarkFlagRequired("out")

	keychainRestoreCmd.Flags().StringVar(&restoreIn, "in", "", "Source backup file path (required)")
	keychainRestoreCmd.Flags().StringVar(&restorePassword, "password", "", "Decryption password (default: prompt)")
	keychainRestoreCmd.Flags().BoolVar(&restoreDryRun, "dry-run", false, "Show what would happen without modifying")
	_ = keychainRestoreCmd.MarkFlagRequired("in")

	keychainCmd.AddCommand(keychainMigrateCmd)
	keychainCmd.AddCommand(keychainBackupCmd)
	keychainCmd.AddCommand(keychainRestoreCmd)
	rootCmd.AddCommand(keychainCmd)
}

// checkKeychainMigrationHint prints a one-time hint if existing items need migration.
func checkKeychainMigrationHint() {
	if keychainGOOS != "darwin" {
		return
	}
	if cfg == nil || (cfg.Auth.UseBiometrics != nil && !*cfg.Auth.UseBiometrics) {
		return
	}
	store, err := getKeyring()
	if err != nil {
		return
	}
	if store.IsKeychainMigrated() {
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
// Precedence: explicit --password flag → prompt. A PIN is not silently reused
// as the password — we always require the user to confirm what they want so
// a forgotten PIN doesn't lock them out of their own backup file.
func resolveBackupPassword(explicit, promptText string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	pw, err := promptPasswordFn(promptText)
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

	pw, err := resolveBackupPassword(backupPassword, "Backup password: ")
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

	pw, err := resolveBackupPassword(restorePassword, "Restore password: ")
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
