package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ApprovalMode controls whether user approval is required before secret injection.
type ApprovalMode string

const (
	ApprovalAlways ApprovalMode = "always"
	ApprovalNever  ApprovalMode = "never"
)

// Rule maps a set of command patterns to the secret patterns they may access.
type Rule struct {
	Commands      []string     `yaml:"commands"`
	Secrets       []string     `yaml:"secrets"`
	Approval      ApprovalMode `yaml:"approval,omitempty"`
	TokenRequired bool         `yaml:"token_required,omitempty"`
}

// Policy is a set of rules loaded from the policy file.
// A nil Policy allows everything (backward compatible).
type Policy struct {
	Approval ApprovalMode `yaml:"approval,omitempty"`
	Rules    []Rule       `yaml:"rules"`
	Proxy    *ProxyPolicy `yaml:"proxy,omitempty"`
}

// Denial is returned when a command is not allowed to access a secret.
type Denial struct {
	Command string
	Secret  string
}

func (d *Denial) Error() string {
	return fmt.Sprintf("policy denied: command %q is not allowed to access secret %q", d.Command, d.Secret)
}

// Load reads the policy file from configDir/policies.yaml.
// Returns (nil, nil) if the file does not exist (allow-all).
// Returns an error if the file exists but is malformed or invalid.
func Load(configDir string) (*Policy, error) {
	policyPath := filepath.Join(configDir, "policies.yaml")

	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	// Validate global approval mode
	if err := validateApproval(pol.Approval, "global"); err != nil {
		return nil, err
	}

	// Validate rules
	for i, rule := range pol.Rules {
		if len(rule.Commands) == 0 {
			return nil, fmt.Errorf("policy rule %d: commands must not be empty", i)
		}
		if len(rule.Secrets) == 0 {
			return nil, fmt.Errorf("policy rule %d: secrets must not be empty", i)
		}
		if err := validateApproval(rule.Approval, fmt.Sprintf("rule %d", i)); err != nil {
			return nil, err
		}
	}

	// Validate proxy rules if present
	if pol.Proxy != nil {
		if err := ValidateProxyRules(pol.Proxy); err != nil {
			return nil, err
		}
	}

	return &pol, nil
}

func validateApproval(mode ApprovalMode, context string) error {
	switch mode {
	case "", ApprovalNever, ApprovalAlways:
		return nil
	default:
		return fmt.Errorf("policy %s: invalid approval mode %q (must be %q, %q, or omitted)", context, mode, ApprovalAlways, ApprovalNever)
	}
}

// RequiresApproval returns true if any of the requested secrets require user
// approval for the given command. A nil Policy never requires approval.
func (p *Policy) RequiresApproval(command string, secretNames []string) bool {
	if p == nil {
		return false
	}
	if len(secretNames) == 0 {
		return false
	}

	base := filepath.Base(command)

	for _, secret := range secretNames {
		if p.secretRequiresApproval(base, secret) {
			return true
		}
	}
	return false
}

// secretRequiresApproval checks a single secret against the rules.
// Returns true if the effective approval mode is "always".
// Fail-closed: if no matching rule is found, returns true.
func (p *Policy) secretRequiresApproval(command, secret string) bool {
	for _, rule := range p.Rules {
		if matchesAny(command, rule.Commands) && matchesAny(secret, rule.Secrets) {
			mode := rule.Approval
			if mode == "" {
				mode = p.Approval
			}
			return mode == ApprovalAlways
		}
	}
	// No matching rule — fail closed
	return true
}

// RequiresToken returns true if any of the requested secrets require a valid
// access token for the given command. A nil Policy never requires a token.
func (p *Policy) RequiresToken(command string, secretNames []string) bool {
	if p == nil {
		return false
	}
	if len(secretNames) == 0 {
		return false
	}

	base := filepath.Base(command)

	for _, secret := range secretNames {
		if p.secretRequiresToken(base, secret) {
			return true
		}
	}
	return false
}

// secretRequiresToken checks a single secret against the rules.
// Returns true if a matching rule has token_required: true.
// No matching rule returns false (backward compatible — tokens are opt-in).
func (p *Policy) secretRequiresToken(command, secret string) bool {
	for _, rule := range p.Rules {
		if matchesAny(command, rule.Commands) && matchesAny(secret, rule.Secrets) {
			return rule.TokenRequired
		}
	}
	return false
}

// Check verifies that the given command is allowed to access all requested secrets.
// A nil Policy allows everything. Empty secretNames are always allowed.
func (p *Policy) Check(command string, secretNames []string) error {
	if p == nil {
		return nil
	}
	if len(secretNames) == 0 {
		return nil
	}

	// Strip to base binary name so full paths work
	base := filepath.Base(command)

	for _, secret := range secretNames {
		if !p.allowed(base, secret) {
			return &Denial{Command: base, Secret: secret}
		}
	}
	return nil
}

// allowed returns true if any rule permits the command+secret pair.
func (p *Policy) allowed(command, secret string) bool {
	for _, rule := range p.Rules {
		if matchesAny(command, rule.Commands) && matchesAny(secret, rule.Secrets) {
			return true
		}
	}
	return false
}

// matchesAny returns true if value matches any of the given glob patterns.
// Malformed patterns are treated as non-matching.
func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, err := path.Match(pattern, value); err == nil && matched {
			return true
		}
	}
	return false
}
