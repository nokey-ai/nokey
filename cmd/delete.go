package cmd

import (
	"fmt"
	"os"

	"github.com/nokey-ai/nokey/internal/audit"
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

	// Record audit entry if audit logging is enabled
	if cfg.Audit.Enabled {
		entry := audit.NewAuditEntry(
			"delete",
			key,
			"none", // delete operation doesn't require auth
			[]string{key},
			err == nil,
			"",
		)
		if err != nil {
			entry.ErrorMessage = err.Error()
		}

		// Record audit entry (ignore errors to not disrupt execution)
		if auditErr := audit.Record(store, entry, cfg.Audit.MaxEntries, cfg.Audit.RetentionDays); auditErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to record audit entry: %v\n", auditErr)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to delete secret %q: %w", key, err)
	}

	fmt.Printf("Secret '%s' deleted successfully\n", key)
	return nil
}
