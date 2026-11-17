package cmd

import (
	"fmt"

	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/keyring"
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
may read the secret. It therefore asks for Touch ID, the login password
or your PIN.

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

	err = confirmRename(cmd, store, oldKey, newKey)
	if err == nil {
		err = store.Rename(oldKey, newKey)
	}

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

// confirmRename asks the person at the machine to approve the rename, as
// the MCP rename_secret tool always does: an agent with a shell would
// otherwise move a secret under a more permissive rule and read it through
// that rule's command. A rename that can't happen is left for Rename to
// refuse, so nobody is asked to approve one.
func confirmRename(cmd *cobra.Command, store *keyring.Store, oldKey, newKey string) error {
	if keyring.ValidateSecretName(newKey) != nil || oldKey == newKey {
		return nil
	}
	existing, err := storedAmong(store, oldKey, newKey)
	if err != nil {
		return err
	}
	if len(existing) != 1 || existing[0] != oldKey {
		return nil
	}
	return confirmHuman(cmdContext(cmd), store, fmt.Sprintf("rename the secret %s to %s", approval.Quote(oldKey), approval.Quote(newKey)), false)
}
