package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nokey-ai/nokey/internal/metadata"
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

	ms, _ := metadata.DefaultStore()

	maxIdleDays := 0
	if cfg != nil {
		maxIdleDays = cfg.SecretPolicy.MaxIdleDays
	}

	fmt.Printf("Stored secrets (%d):\n", len(keys))
	for _, key := range keys {
		suffix := ""
		if ms != nil {
			if meta, _ := ms.GetMeta(key); meta != nil {
				age := formatDuration(time.Since(meta.CreatedAt))
				if !meta.CreatedAt.IsZero() {
					suffix = fmt.Sprintf("  (age: %s", age)
				}
				if !meta.LastAccessed.IsZero() {
					idle := time.Since(meta.LastAccessed)
					suffix += fmt.Sprintf(", idle: %s", formatDuration(idle))
					if maxIdleDays > 0 && idle > time.Duration(maxIdleDays)*24*time.Hour {
						suffix += " [STALE]"
					}
				}
				if suffix != "" {
					suffix += ")"
				}
			}
		}
		fmt.Printf("  %s%s\n", key, suffix)
	}

	return nil
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 365 {
		return fmt.Sprintf("%dy", days/365)
	}
	if days >= 30 {
		return fmt.Sprintf("%dmo", days/30)
	}
	if days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d.Hours())
	if hours >= 1 {
		return fmt.Sprintf("%dh", hours)
	}
	return "<1h"
}
