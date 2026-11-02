package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var renameCmd = &cobra.Command{
	Use:     "rename OLD NEW",
	Aliases: []string{"mv"},
	Short:   "Rename a stored secret",
	Long: `Rename a stored secret in the OS keyring, keeping its value.

The value is copied to the new name, checked, and then removed from the
old name. Renaming onto a name that already exists is refused; delete
that secret first if you mean to replace it.

Policy rules match secret names, so a rename can change which commands
may read the secret.

Example:
  nokey rename OPENAI_KEY OPENAI_API_KEY`,
	Args: cobra.ExactArgs(2),
	RunE: runRename,
}

func init() {
	rootCmd.AddCommand(renameCmd)
}

func runRename(cmd *cobra.Command, args []string) error {
	oldKey, newKey := args[0], args[1]

	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	err = store.Rename(oldKey, newKey)

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	AppFromCmd(cmd).RecordAudit(store, "rename", oldKey, "none", []string{oldKey, newKey}, err == nil, errMsg)

	if err != nil {
		return fmt.Errorf("failed to rename secret %q: %w", oldKey, err)
	}

	fmt.Printf("Secret '%s' renamed to '%s'\n", oldKey, newKey)
	return nil
}
