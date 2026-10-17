package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/spf13/cobra"
)

var configValidateJSON bool

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate config and policy files",
	Long: `Load and validate config.yaml and policies.yaml, reporting any errors.
Exits with code 1 if either file is invalid.

With --json, both files are always checked and the result is printed as
{"config": {...}, "policy": {...}}.`,
	RunE: runConfigValidate,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configValidateCmd)
	configValidateCmd.Flags().BoolVar(&configValidateJSON, "json", false, "Output as JSON")
}

type fileValidation struct {
	Path  string `json:"path,omitempty"`
	Found bool   `json:"found"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

func runConfigValidateJSONOutput() error {
	var cfgRes, polRes fileValidation

	if path, err := config.ConfigPath(); err == nil {
		cfgRes.Path = path
		_, statErr := os.Stat(path)
		cfgRes.Found = statErr == nil
	}
	if _, err := config.LoadStrict(); err != nil {
		cfgRes.Error = err.Error()
	} else {
		cfgRes.Valid = true
	}

	if configDir, err := getConfigDir(); err != nil {
		polRes.Error = fmt.Sprintf("failed to determine config directory: %s", err)
	} else {
		polRes.Path = filepath.Join(configDir, "policies.yaml")
		if pol, err := policy.LoadStrict(configDir); err != nil {
			polRes.Found = true
			polRes.Error = err.Error()
		} else {
			polRes.Found = pol != nil
			polRes.Valid = true
		}
	}

	data, err := json.MarshalIndent(map[string]fileValidation{"config": cfgRes, "policy": polRes}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))

	if !cfgRes.Valid || !polRes.Valid {
		return fmt.Errorf("validation failed")
	}
	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	if configValidateJSON {
		return runConfigValidateJSONOutput()
	}

	// Validate config (strict mode catches unknown keys / typos)
	_, err := config.LoadStrict()
	if err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	fmt.Println("config.yaml: OK")

	// Validate policy (strict mode catches unknown keys / typos)
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to determine config directory: %w", err)
	}

	pol, err := policy.LoadStrict(configDir)
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
