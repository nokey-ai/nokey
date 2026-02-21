package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all stored secret keys",
	Long: `List all stored secret keys (names only, never values).

Example:
  nokey list`,
	RunE: runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return err
	}

	keys, err := store.List()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No secrets stored")
		return nil
	}

	fmt.Printf("Stored secrets (%d):\n", len(keys))
	for _, key := range keys {
		fmt.Printf("  %s\n", key)
	}

	return nil
}
