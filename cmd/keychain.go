package cmd

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var keychainCmd = &cobra.Command{
	Use:   "keychain",
	Short: "macOS Keychain management commands",
}

var keychainMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Re-create keychain items with trusted-app ACL to eliminate prompts",
	Long: `On macOS, existing keychain items may prompt for authorization on every access.
This command re-creates all nokey items so the nokey binary is added to each
item's trusted-app ACL, allowing silent access without prompts.

This is only needed on macOS and only for items created before trust was enabled.
New items are automatically created with the correct ACL.`,
	RunE: runKeychainMigrate,
}

var (
	migrateDryRun bool
	migrateYes    bool
)

func init() {
	keychainMigrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Show what would be migrated without modifying")
	keychainMigrateCmd.Flags().BoolVar(&migrateYes, "yes", false, "Skip confirmation prompt")
	keychainCmd.AddCommand(keychainMigrateCmd)
	rootCmd.AddCommand(keychainCmd)
}

func runKeychainMigrate(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "darwin" {
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
		fmt.Printf("This will re-create %d keychain item(s) with trusted-app ACL.\n", len(keys))
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

	fmt.Printf("Migrated %d keychain item(s). Keychain prompts should no longer appear.\n", count)
	return nil
}
