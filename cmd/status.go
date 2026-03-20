package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/spf13/cobra"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show nokey health check and configuration status",
	Long: `Display the current state of nokey: PIN authentication, keyring access,
configuration validity, policy rules, and stored secrets count.`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON")
}

type statusOutput struct {
	Keyring    string `json:"keyring"`
	PIN        string `json:"pin"`
	Config     string `json:"config"`
	Policy     string `json:"policy"`
	PolicyRule int    `json:"policy_rules"`
	ProxyRules int    `json:"proxy_rules"`
	Secrets    int    `json:"secrets"`
}

func runStatus(cmd *cobra.Command, args []string) error {
	out := statusOutput{}

	// Keyring / PIN
	store, err := getKeyring()
	if err != nil {
		out.Keyring = fmt.Sprintf("error: %s", err)
		out.PIN = "unknown"
	} else {
		out.Keyring = "accessible"
		if store.HasPIN() {
			out.PIN = "configured"
		} else {
			out.PIN = "not configured"
		}
	}

	// Config
	if cfg != nil {
		out.Config = "valid"
	} else {
		out.Config = "not loaded"
	}

	// Policy
	configDir, dirErr := getConfigDir()
	if dirErr == nil {
		pol, polErr := policy.Load(configDir)
		if polErr != nil {
			out.Policy = fmt.Sprintf("error: %s", polErr)
		} else if pol == nil {
			out.Policy = "no policies.yaml (allow-all)"
		} else {
			out.Policy = "valid"
			out.PolicyRule = len(pol.Rules)
			if pol.Proxy != nil {
				out.ProxyRules = len(pol.ProxyRules())
			}
		}
	}

	// Secrets count
	if store != nil {
		keys, listErr := store.List()
		if listErr != nil {
			out.Secrets = -1
		} else {
			out.Secrets = len(keys)
		}
	}

	if statusJSON {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Human-readable output
	fmt.Println("nokey status:")
	fmt.Printf("  Keyring backend:     %s\n", out.Keyring)
	fmt.Printf("  PIN authentication:  %s\n", out.PIN)
	fmt.Printf("  Config:              %s\n", out.Config)
	if out.Policy == "valid" {
		fmt.Printf("  Policy:              valid (%d rules, %d proxy rules)\n", out.PolicyRule, out.ProxyRules)
	} else {
		fmt.Printf("  Policy:              %s\n", out.Policy)
	}
	if out.Secrets >= 0 {
		fmt.Printf("  Secrets stored:      %d\n", out.Secrets)
	} else {
		fmt.Fprintf(os.Stderr, "  Secrets stored:      error\n")
	}

	return nil
}
