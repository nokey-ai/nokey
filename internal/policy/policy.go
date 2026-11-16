package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

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

// Hint tells the user how to allow what d refused. It is meant for an agent
// that hit the denial and cannot edit the policy itself. policyPath is the
// policy file's location, or "" if the caller doesn't know it.
func (d *Denial) Hint(policyPath string) string {
	if policyPath == "" {
		policyPath = "policies.yaml in the nokey config directory"
	}
	return fmt.Sprintf("To allow it, the user can add a rule to %s:\n  rules:\n    - commands: [%q]\n      secrets: [%q]\nand then approve the change with 'nokey policy approve' in a terminal.",
		policyPath, d.Command, d.Secret)
}

// DigestKey is the reserved keyring key holding Digest of the
// policies.yaml the user last approved with `nokey policy approve`. The
// file itself is writable by any process running as the user, so only a
// policy whose digest matches is applied.
const DigestKey = "__nokey_policy_digest__"

// Digest is the hex SHA-256 of policy file contents.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NotApprovedError means policies.yaml differs from the last approved
// version: it was edited, never approved, or removed after approval.
type NotApprovedError struct {
	Path    string
	Removed bool // the file is gone but an approved digest remains
}

func (e *NotApprovedError) Error() string {
	if e.Removed {
		return fmt.Sprintf("%s was removed after it was approved; restore it, or run 'nokey policy approve' in a terminal to approve running without one", e.Path)
	}
	return fmt.Sprintf("%s has not been approved in its current form; review it and run 'nokey policy approve' in a terminal", e.Path)
}

// Path returns the policy file's location in configDir.
func Path(configDir string) string {
	return filepath.Join(configDir, "policies.yaml")
}

// Load reads the policy file from configDir/policies.yaml without
// checking that it was approved: use LoadApproved to enforce a policy.
// Returns (nil, nil) if the file does not exist (allow-all).
// Returns an error if the file exists but is malformed or invalid.
func Load(configDir string) (*Policy, error) {
	data, err := os.ReadFile(Path(configDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return parse(data)
}

// LoadApproved reads policies.yaml like Load, but only if its digest is
// approved, the digest stored under DigestKey ("" if none). With no file
// and no approved digest it returns (nil, nil). Otherwise a file that
// doesn't match, or a missing file with a digest still approved, is a
// *NotApprovedError.
func LoadApproved(configDir, approved string) (*Policy, error) {
	path := Path(configDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if approved != "" {
				return nil, &NotApprovedError{Path: path, Removed: true}
			}
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	if Digest(data) != approved {
		return nil, &NotApprovedError{Path: path}
	}
	return parse(data)
}

// parse unmarshals and validates policy file contents.
func parse(data []byte) (*Policy, error) {
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if err := validatePolicy(&pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

// LoadStrict reads the policy file like Load, but rejects unknown YAML keys.
// Use this for validation commands where typos should be caught.
func LoadStrict(configDir string) (*Policy, error) {
	policyPath := filepath.Join(configDir, "policies.yaml")

	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return ParseStrict(data)
}

// ParseStrict parses and validates policy file contents like LoadStrict,
// rejecting unknown YAML keys.
func ParseStrict(data []byte) (*Policy, error) {
	var pol Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pol); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if err := validatePolicy(&pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

// validatePolicy checks the approval modes, rules and proxy rules of a
// parsed policy.
func validatePolicy(pol *Policy) error {
	// Validate global approval mode
	if err := validateApproval(pol.Approval, "global"); err != nil {
		return err
	}

	// Validate rules
	for i, rule := range pol.Rules {
		if len(rule.Commands) == 0 {
			return fmt.Errorf("policy rule %d: commands must not be empty", i)
		}
		if len(rule.Secrets) == 0 {
			return fmt.Errorf("policy rule %d: secrets must not be empty", i)
		}
		if err := validateApproval(rule.Approval, fmt.Sprintf("rule %d", i)); err != nil {
			return err
		}
	}

	// Validate proxy rules if present
	if pol.Proxy != nil {
		return ValidateProxyRules(pol.Proxy)
	}
	return nil
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

	key := CommandKey(command)

	for _, secret := range secretNames {
		if p.secretRequiresApproval(key, secret) {
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
		if matchesCommand(command, rule.Commands) && matchesAny(secret, rule.Secrets) {
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

	key := CommandKey(command)

	for _, secret := range secretNames {
		if p.secretRequiresToken(key, secret) {
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
		if matchesCommand(command, rule.Commands) && matchesAny(secret, rule.Secrets) {
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

	key := CommandKey(command)

	for _, secret := range secretNames {
		if !p.allowed(key, secret) {
			return &Denial{Command: key, Secret: secret}
		}
	}
	return nil
}

// allowed returns true if any rule permits the command+secret pair.
func (p *Policy) allowed(command, secret string) bool {
	for _, rule := range p.Rules {
		if matchesCommand(command, rule.Commands) && matchesAny(secret, rule.Secrets) {
			return true
		}
	}
	return false
}

// CommandKey is how rules, tokens and grants identify a command: a bare
// name as given, or a path made absolute and cleaned. A path is never
// reduced to its last element, so /tmp/evil/gh is not "gh": any program
// can be put at a path with a trusted name.
func CommandKey(command string) string {
	if !isPath(command) {
		return command
	}
	if abs, err := filepath.Abs(command); err == nil {
		return abs
	}
	return filepath.Clean(command)
}

// MatchCommand reports whether a command pattern covers key, a CommandKey.
// "*" covers every command. Otherwise a pattern with no path separator
// covers commands given by bare name, which run from the PATH of the
// process running nokey, and a pattern with one covers commands given as
// a matching path. Malformed patterns match nothing.
func MatchCommand(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	if isPath(pattern) != isPath(key) {
		return false
	}
	matched, err := path.Match(filepath.ToSlash(pattern), filepath.ToSlash(key))
	return err == nil && matched
}

func isPath(s string) bool {
	return strings.ContainsRune(s, '/') || strings.ContainsRune(s, filepath.Separator)
}

// matchesCommand reports whether key matches any of the command patterns.
func matchesCommand(key string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchCommand(pattern, key) {
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
