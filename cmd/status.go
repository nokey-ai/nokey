package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/metadata"
	"github.com/nokey-ai/nokey/internal/oauth"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/session"
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
	Keyring      string `json:"keyring"`
	PIN          string `json:"pin"`
	OAuth        string `json:"oauth"`
	Config       string `json:"config"`
	Policy       string `json:"policy"`
	PolicyRule   int    `json:"policy_rules"`
	ProxyRules   int    `json:"proxy_rules"`
	Secrets      int    `json:"secrets"`
	AuditHealth  string `json:"audit_health"`
	AuditEntries int    `json:"audit_entries,omitempty"`
	Session      string `json:"session"`
	StaleSecrets int    `json:"stale_secrets,omitempty"`
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

	// OAuth status
	out.OAuth = "not configured"
	if cfg != nil && store != nil {
		var providerName string
		if cfg.Auth.OAuth.GitHub.Enabled {
			providerName = "github"
		} else if cfg.Auth.OAuth.Custom.Enabled {
			providerName = "generic"
		}
		if providerName != "" {
			token, tokenErr := oauth.LoadToken(store, providerName)
			if tokenErr != nil {
				out.OAuth = fmt.Sprintf("%s (no token)", providerName)
			} else if token.IsExpired() {
				out.OAuth = fmt.Sprintf("%s (expired)", providerName)
			} else {
				out.OAuth = fmt.Sprintf("%s (valid)", providerName)
			}
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

	// Audit health
	if cfg != nil && cfg.Audit.Enabled {
		if store != nil {
			auditLog, loadErr := audit.Load(store)
			if loadErr != nil {
				out.AuditHealth = fmt.Sprintf("error: %s", loadErr)
			} else {
				out.AuditHealth = "enabled"
				out.AuditEntries = len(auditLog.Entries)
				if len(auditLog.Warnings) > 0 {
					out.AuditHealth = fmt.Sprintf("enabled (%d warnings)", len(auditLog.Warnings))
				}
			}
		}
	} else {
		out.AuditHealth = "disabled"
	}

	// Session status
	if store != nil && store.HasPIN() {
		storedHash, hashErr := store.GetPINHash()
		if hashErr == nil {
			ttl, _ := session.ParseTTL(cfg.Auth.SessionTTL)
			if session.Valid(storedHash, ttl) {
				out.Session = "active"
			} else {
				out.Session = "expired"
			}
		} else {
			out.Session = "no PIN"
		}
	} else {
		out.Session = "n/a"
	}

	// Stale secrets (from metadata)
	if ms, msErr := metadata.DefaultStore(); msErr == nil {
		stale, staleErr := ms.ListStale(90 * 24 * time.Hour)
		if staleErr == nil {
			out.StaleSecrets = len(stale)
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
	fmt.Printf("  OAuth:               %s\n", out.OAuth)
	fmt.Printf("  Session:             %s\n", out.Session)
	if out.Policy == "valid" {
		fmt.Printf("  Policy:              valid (%d rules, %d proxy rules)\n", out.PolicyRule, out.ProxyRules)
	} else {
		fmt.Printf("  Policy:              %s\n", out.Policy)
	}
	fmt.Printf("  Config:              %s\n", out.Config)
	if out.Secrets >= 0 {
		fmt.Printf("  Secrets stored:      %d\n", out.Secrets)
	} else {
		fmt.Fprintf(os.Stderr, "  Secrets stored:      error\n")
	}
	fmt.Printf("  Audit:               %s\n", out.AuditHealth)
	if out.AuditEntries > 0 {
		fmt.Printf("  Audit entries:       %d\n", out.AuditEntries)
	}
	if out.StaleSecrets > 0 {
		fmt.Printf("  Stale secrets:       %d (not accessed in 90+ days)\n", out.StaleSecrets)
	}

	return nil
}
