package cmd

import (
	"fmt"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate config and policy files",
	Long: `Load and validate config.yaml and policies.yaml, reporting any errors.
Exits with code 1 if either file is invalid.`,
	RunE: runConfigValidate,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configValidateCmd)
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	// Validate config
	_, err := config.Load()
	if err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	fmt.Println("config.yaml: OK")

	// Validate policy
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to determine config directory: %w", err)
	}

	pol, err := policy.Load(configDir)
	if err != nil {
		return fmt.Errorf("policies.yaml: %w", err)
	}
	if pol == nil {
		fmt.Println("policies.yaml: not found (allow-all)")
	} else {
		fmt.Println("policies.yaml: OK")
	}

	return nil
}
