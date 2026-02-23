package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule maps a set of command patterns to the secret patterns they may access.
type Rule struct {
	Commands []string `yaml:"commands"`
	Secrets  []string `yaml:"secrets"`
}

// Policy is a set of rules loaded from the policy file.
// A nil Policy allows everything (backward compatible).
type Policy struct {
	Rules []Rule `yaml:"rules"`
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

	// Validate rules
	for i, rule := range pol.Rules {
		if len(rule.Commands) == 0 {
			return nil, fmt.Errorf("policy rule %d: commands must not be empty", i)
		}
		if len(rule.Secrets) == 0 {
			return nil, fmt.Errorf("policy rule %d: secrets must not be empty", i)
		}
	}

	return &pol, nil
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
