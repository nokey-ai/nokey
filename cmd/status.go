package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/version"
	"github.com/spf13/cobra"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show nokey health check and configuration status",
	Long: `Display the current state of nokey: PIN authentication, keyring access,
configuration validity, policy rules, and stored secrets count.

status always exits 0; use 'nokey doctor' for a check that fails on problems.`,
	RunE: runStatus,
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the nokey setup and suggest fixes",
	Long: `Run the same checks as 'nokey status', print a hint for each problem,
and exit non-zero if any check fails. Warnings (such as no PIN configured)
are reported but do not fail.`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(doctorCmd)
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON")
}

type statusOutput struct {
	Keyring      string `json:"keyring"`
	PIN          string `json:"pin"`
	Config       string `json:"config"`
	Policy       string `json:"policy"`
	PolicyRule   int    `json:"policy_rules"`
	ProxyRules   int    `json:"proxy_rules"`
	Secrets      int    `json:"secrets"`
	AuditEnabled bool   `json:"audit_enabled"`
	AuthMethod   string `json:"auth_method"`
	ConfigDir    string `json:"config_dir"`
	CAPresent    bool   `json:"ca_present"`
	Version      string `json:"version"`
}

// statusReport holds the status output plus the underlying errors so that
// doctor can turn them into pass/fail checks.
type statusReport struct {
	out        statusOutput
	keyringErr error
	configErr  error
	dirErr     error
	policyErr  error
	strictErr  error // policies.yaml loads, but has keys Load silently ignores
	listErr    error
	pinSet     bool
}

func collectStatus() *statusReport {
	r := &statusReport{out: statusOutput{Version: version.Version}}
	out := &r.out

	// Keyring / PIN
	store, err := getKeyring()
	if err != nil {
		r.keyringErr = err
		out.Keyring = fmt.Sprintf("error: %s", err)
		out.PIN = "unknown"
	} else {
		out.Keyring = "accessible"
		if store.HasPIN() {
			r.pinSet = true
			out.PIN = "configured"
		} else {
			out.PIN = "not configured"
		}
	}

	// Config: re-read strictly, since the loaded cfg silently falls back to
	// defaults when config.yaml is broken.
	if _, err := config.LoadStrict(); err != nil {
		r.configErr = err
		out.Config = fmt.Sprintf("error: %s", err)
	} else {
		out.Config = "valid"
	}

	if cfg != nil {
		out.AuditEnabled = cfg.Audit.Enabled
		out.AuthMethod = cfg.Auth.DefaultMethod
		if out.AuthMethod == "" {
			// Same fallback as exec: PIN if configured, otherwise none
			if cfg.RequireAuth || r.pinSet {
				out.AuthMethod = "pin"
			} else {
				out.AuthMethod = "none"
			}
		}
	}

	// Policy
	configDir, dirErr := getConfigDir()
	if dirErr != nil {
		r.dirErr = dirErr
	} else {
		out.ConfigDir = configDir
		if _, err := os.Stat(filepath.Join(configDir, "ca", "ca-cert.pem")); err == nil {
			out.CAPresent = true
		}

		pol, polErr := policy.Load(configDir)
		if polErr != nil {
			r.policyErr = polErr
			out.Policy = fmt.Sprintf("error: %s", polErr)
		} else if pol == nil {
			out.Policy = "no policies.yaml (allow-all)"
		} else {
			out.Policy = "valid"
			out.PolicyRule = len(pol.Rules)
			if pol.Proxy != nil {
				out.ProxyRules = len(pol.ProxyRules())
			}
			if _, err := policy.LoadStrict(configDir); err != nil {
				r.strictErr = err
			}
		}
	}

	// Secrets count
	if store != nil {
		keys, listErr := store.List()
		if listErr != nil {
			r.listErr = listErr
			out.Secrets = -1
		} else {
			out.Secrets = len(keys)
		}
	}

	return r
}

func runStatus(cmd *cobra.Command, args []string) error {
	out := collectStatus().out

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
	fmt.Printf("  Version:             %s\n", out.Version)
	fmt.Printf("  Keyring backend:     %s\n", out.Keyring)
	fmt.Printf("  PIN authentication:  %s\n", out.PIN)
	fmt.Printf("  Auth method:         %s\n", out.AuthMethod)
	fmt.Printf("  Config:              %s\n", out.Config)
	fmt.Printf("  Config dir:          %s\n", out.ConfigDir)
	if out.Policy == "valid" {
		fmt.Printf("  Policy:              valid (%d rules, %d proxy rules)\n", out.PolicyRule, out.ProxyRules)
	} else {
		fmt.Printf("  Policy:              %s\n", out.Policy)
	}
	fmt.Printf("  Audit logging:       %s\n", enabledString(out.AuditEnabled))
	fmt.Printf("  Proxy CA:            %s\n", presentString(out.CAPresent))
	if out.Secrets >= 0 {
		fmt.Printf("  Secrets stored:      %d\n", out.Secrets)
	} else {
		fmt.Fprintf(os.Stderr, "  Secrets stored:      error\n")
	}

	return nil
}

func enabledString(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

func presentString(b bool) string {
	if b {
		return "present"
	}
	return "not created yet (created on first 'nokey proxy start')"
}

const (
	checkOK   = "OK"
	checkWarn = "WARN"
	checkFail = "FAIL"
)

type doctorCheck struct {
	level  string
	name   string
	detail string
	hint   string
}

// doctorChecks turns a status report into checks with fix-it hints.
func doctorChecks(r *statusReport) []doctorCheck {
	var checks []doctorCheck
	add := func(level, name, detail, hint string) {
		checks = append(checks, doctorCheck{level, name, detail, hint})
	}

	configPath := "config.yaml"
	if r.out.ConfigDir != "" {
		configPath = filepath.Join(r.out.ConfigDir, "config.yaml")
	}

	if r.dirErr != nil {
		add(checkFail, "config dir", r.dirErr.Error(), "Make sure $HOME (or %APPDATA% on Windows) is set")
	} else if _, err := os.Stat(r.out.ConfigDir); err != nil {
		add(checkWarn, "config dir", fmt.Sprintf("%s does not exist", r.out.ConfigDir), "Run 'nokey init' to create a starter config")
	} else {
		add(checkOK, "config dir", r.out.ConfigDir, "")
	}

	if r.configErr != nil {
		add(checkFail, "config", r.configErr.Error(), fmt.Sprintf("Fix %s, then run 'nokey config validate'", configPath))
	} else {
		add(checkOK, "config", "valid", "")
	}

	if r.policyErr != nil {
		add(checkFail, "policies.yaml", r.policyErr.Error(), "Fix policies.yaml, then run 'nokey config validate'")
	} else if r.strictErr != nil {
		add(checkFail, "policies.yaml", r.strictErr.Error(), "Unknown keys are ignored at runtime; fix the typo, then run 'nokey config validate'")
	} else if r.dirErr == nil {
		add(checkOK, "policies.yaml", r.out.Policy, "")
	}

	if r.keyringErr != nil {
		add(checkFail, "keyring", r.keyringErr.Error(), "Check --backend / NOKEY_BACKEND and default_backend in config.yaml")
	} else if r.listErr != nil {
		add(checkFail, "keyring", fmt.Sprintf("cannot list secrets: %s", r.listErr), "Unlock the keyring or check its access settings")
	} else {
		add(checkOK, "keyring", fmt.Sprintf("accessible (%d secrets)", r.out.Secrets), "")
	}

	if r.keyringErr == nil {
		if r.pinSet {
			add(checkOK, "PIN", "configured", "")
		} else {
			add(checkWarn, "PIN", "not configured; anything that can run nokey can read secrets", "Run 'nokey auth setup' to require a PIN")
		}
	}

	if r.out.AuditEnabled {
		add(checkOK, "audit log", "enabled", "")
	} else {
		add(checkWarn, "audit log", "disabled", fmt.Sprintf("Set audit.enabled: true in %s", configPath))
	}

	return checks
}

func runDoctor(cmd *cobra.Command, args []string) error {
	checks := doctorChecks(collectStatus())

	failed := 0
	for _, c := range checks {
		fmt.Printf("[%-4s] %-14s %s\n", c.level, c.name, c.detail)
		if c.hint != "" {
			fmt.Printf("       %-14s -> %s\n", "", c.hint)
		}
		if c.level == checkFail {
			failed++
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("\nNo problems found.")
	return nil
}
