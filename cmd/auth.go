package cmd

import (
	"fmt"

	"github.com/nokey-ai/nokey/internal/auth"
	"github.com/nokey-ai/nokey/internal/session"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication (PIN setup/change/disable)",
	Long: `Manage PIN-based authentication for zero-trust secret access.

When authentication is enabled, you must enter your PIN every time
you access secrets. This prevents AI assistants or automated tools
from accessing your secrets without your explicit approval.

Subcommands:
  setup    - Create a new PIN
  change   - Change your existing PIN
  disable  - Remove PIN requirement
  status   - Check if PIN is configured`,
}

var authSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up PIN-based authentication",
	Long: `Create a PIN that must be entered before accessing secrets.

This enables zero-trust security: even if an AI assistant runs
'nokey exec', it cannot access secrets without you entering the PIN.

The PIN is hashed and stored securely in your OS keyring.`,
	RunE: runAuthSetup,
}

var authChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change your existing PIN",
	Long:  `Change your PIN by entering the old PIN followed by a new one.`,
	RunE:  runAuthChange,
}

var authDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable PIN authentication",
	Long: `Remove the PIN requirement and return to the previous security model.

You will need to enter your current PIN to confirm.`,
	RunE: runAuthDisable,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check authentication status",
	Long:  `Check if PIN authentication is currently configured.`,
	RunE:  runAuthStatus,
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(authSetupCmd)
	authCmd.AddCommand(authChangeCmd)
	authCmd.AddCommand(authDisableCmd)
	authCmd.AddCommand(authStatusCmd)

}

// Injectable auth functions for testing.
var (
	authSetupPINFn     = auth.SetupPIN
	authChangePINFn    = auth.ChangePIN
	authAuthenticateFn = auth.Authenticate
)

func runAuthSetup(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Check if PIN already exists
	if store.HasPIN() {
		return fmt.Errorf("PIN already configured\nUse 'nokey auth change' to change it or 'nokey auth disable' to remove it")
	}

	// Set up new PIN
	hash, err := authSetupPINFn()
	if err != nil {
		return err
	}

	// Store the hash
	if err := store.SetPINHash(hash); err != nil {
		return err
	}

	fmt.Println("✅ PIN authentication enabled")
	fmt.Println("\nTo use PIN authentication with exec:")
	fmt.Println("  nokey exec -- command")
	fmt.Println("\nOr enable it by default in ~/.config/nokey/config.yaml:")
	fmt.Println("  auth:")
	fmt.Println("    default_method: pin")

	return nil
}

func runAuthChange(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Get old PIN hash
	oldHash, err := store.GetPINHash()
	if err != nil {
		return err
	}

	// Change PIN (verifies old PIN first)
	newHash, err := authChangePINFn(oldHash)
	if err != nil {
		return err
	}

	// Store new hash
	if err := store.SetPINHash(newHash); err != nil {
		return err
	}

	// Invalidate any active session ticket.
	_ = session.Clear()

	fmt.Println("\n✅ PIN changed successfully")
	return nil
}

func runAuthDisable(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Get PIN hash
	storedHash, err := store.GetPINHash()
	if err != nil {
		return err
	}

	// Verify current PIN before disabling
	fmt.Println("To disable PIN authentication, verify your current PIN:")
	if err := authAuthenticateFn(storedHash); err != nil {
		return err
	}

	// Delete PIN hash
	if err := store.DeletePINHash(); err != nil {
		return err
	}

	// Remove any active session ticket.
	_ = session.Clear()

	fmt.Println("\n✅ PIN authentication disabled")
	fmt.Println("⚠️  Secrets can now be accessed without PIN verification")

	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	if store.HasPIN() {
		fmt.Println("🔐 PIN authentication: ENABLED")
		fmt.Println("\nSecrets require PIN entry before access.")
		fmt.Println("\nCommands:")
		fmt.Println("  nokey auth change   - Change your PIN")
		fmt.Println("  nokey auth disable  - Disable PIN authentication")
	} else {
		fmt.Println("🔓 PIN authentication: DISABLED")
		fmt.Println("\nSecrets can be accessed without PIN verification.")
		fmt.Println("\nTo enable:")
		fmt.Println("  nokey auth setup")
	}

	return nil
}
