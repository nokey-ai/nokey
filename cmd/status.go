package cmd

import (
	"fmt"
	"os"

	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show nokey health check and configuration status",
	Long: `Display the current state of nokey: PIN authentication, keyring access,
configuration validity, policy rules, and stored secrets count.`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("nokey status:")

	// PIN authentication
	store, err := getKeyring()
	if err != nil {
		fmt.Printf("  Keyring backend:     error (%s)\n", err)
		return nil
	}

	if store.HasPIN() {
		fmt.Println("  PIN authentication:  configured")
	} else {
		fmt.Println("  PIN authentication:  not configured")
	}

	// Keyring accessible
	fmt.Println("  Keyring backend:     accessible")

	// Config
	if cfg != nil {
		fmt.Println("  Config:              valid")
	} else {
		fmt.Println("  Config:              not loaded")
	}

	// Policy
	configDir, err := getConfigDir()
	if err == nil {
		pol, polErr := policy.Load(configDir)
		if polErr != nil {
			fmt.Printf("  Policy:              error (%s)\n", polErr)
		} else if pol == nil {
			fmt.Println("  Policy:              no policies.yaml (allow-all)")
		} else {
			ruleCount := len(pol.Rules)
			proxyCount := 0
			if pol.Proxy != nil {
				proxyCount = len(pol.ProxyRules())
			}
			fmt.Printf("  Policy:              valid (%d rules, %d proxy rules)\n", ruleCount, proxyCount)
		}
	}

	// Secrets count
	keys, err := store.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Secrets stored:      error (%s)\n", err)
	} else {
		fmt.Printf("  Secrets stored:      %d\n", len(keys))
	}

	return nil
}
