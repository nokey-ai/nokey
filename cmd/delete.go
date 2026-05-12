package cmd

import (
	"fmt"

	"github.com/nokey-ai/nokey/internal/metadata"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:     "delete KEY",
	Aliases: []string{"rm", "remove"},
	Short:   "Remove a stored secret",
	Long: `Remove a stored secret from the OS keyring.

Example:
  nokey delete OPENAI_API_KEY`,
	Args: cobra.ExactArgs(1),
	RunE: runDelete,
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}

func runDelete(cmd *cobra.Command, args []string) error {
	key := args[0]

	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	err = store.Delete(key)

	// Record audit entry
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	AppFromCmd(cmd).RecordAudit(store, "delete", key, "none", []string{key}, err == nil, errMsg)

	if err != nil {
		return fmt.Errorf("failed to delete secret %q: %w", key, err)
	}

	if ms, msErr := metadata.DefaultStore(); msErr == nil {
		_ = ms.Remove(key)
	}

	fmt.Printf("Secret '%s' deleted successfully\n", key)
	return nil
}
