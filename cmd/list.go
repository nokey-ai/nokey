package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var listJSON bool

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all stored secret keys",
	Long: `List all stored secret keys (names only, never values).

Example:
  nokey list
  nokey list --json`,
	RunE: runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
}

func runList(cmd *cobra.Command, args []string) error {
	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w\n\nRun 'nokey status' to check your setup", err)
	}

	keys, err := store.List()
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if listJSON {
		out := struct {
			Secrets []string `json:"secrets"`
			Count   int      `json:"count"`
		}{
			Secrets: keys,
			Count:   len(keys),
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
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
