package policy

import (
	"fmt"
	"path"
	"regexp"
)

// secretRefRe matches $SECRET_NAME references in header values.
// Doubled $$ is a literal dollar sign and is skipped.
var secretRefRe = regexp.MustCompile(`\$\$|\$([A-Za-z_][A-Za-z0-9_]*)`)

// ProxyPolicy configures the HTTP/HTTPS intercept proxy.
type ProxyPolicy struct {
	Approval ApprovalMode `yaml:"approval,omitempty"`
	Rules    []ProxyRule  `yaml:"rules"`
}

// ProxyRule maps a set of host patterns to headers that should be injected.
type ProxyRule struct {
	Hosts    []string          `yaml:"hosts"`
	Headers  map[string]string `yaml:"headers"`
	Approval ApprovalMode      `yaml:"approval,omitempty"`
	// Secrets is computed during validation — not serialized.
	Secrets []string `yaml:"-"`
}

// ValidateProxyRules validates all proxy rules and extracts secret references
// into each rule's Secrets field. Returns an error on the first invalid rule.
func ValidateProxyRules(pp *ProxyPolicy) error {
	if pp == nil {
		return nil
	}

	if err := validateApproval(pp.Approval, "proxy global"); err != nil {
		return err
	}

	for i := range pp.Rules {
		rule := &pp.Rules[i]

		if len(rule.Hosts) == 0 {
			return fmt.Errorf("proxy rule %d: hosts must not be empty", i)
		}
		if len(rule.Headers) == 0 {
			return fmt.Errorf("proxy rule %d: headers must not be empty", i)
		}
		if err := validateApproval(rule.Approval, fmt.Sprintf("proxy rule %d", i)); err != nil {
			return err
		}

		// Extract secret references from header values.
		seen := make(map[string]bool)
		for _, val := range rule.Headers {
			for _, match := range secretRefRe.FindAllStringSubmatch(val, -1) {
				name := match[1]
				if name != "" && !seen[name] {
					seen[name] = true
					rule.Secrets = append(rule.Secrets, name)
				}
			}
		}
		if len(rule.Secrets) == 0 {
			return fmt.Errorf("proxy rule %d: headers must reference at least one secret ($SECRET_NAME)", i)
		}
	}

	return nil
}

// ProxyRules returns the proxy rules, or nil if no proxy section is configured.
func (p *Policy) ProxyRules() []ProxyRule {
	if p == nil || p.Proxy == nil {
		return nil
	}
	return p.Proxy.Rules
}

// ProxyRequiresApproval returns true if any matching proxy rule requires user
// approval for the given host and secret names. A nil Policy never requires approval.
func (p *Policy) ProxyRequiresApproval(host string, secretNames []string) bool {
	if p == nil || p.Proxy == nil {
		return false
	}
	if len(secretNames) == 0 {
		return false
	}

	for _, secret := range secretNames {
		if p.proxySecretRequiresApproval(host, secret) {
			return true
		}
	}
	return false
}

// proxySecretRequiresApproval checks a single secret against the proxy rules.
// Fail-closed: if no matching rule is found, returns true.
func (p *Policy) proxySecretRequiresApproval(host, secret string) bool {
	for _, rule := range p.Proxy.Rules {
		if matchesAnyHost(host, rule.Hosts) && containsSecret(secret, rule.Secrets) {
			mode := rule.Approval
			if mode == "" {
				mode = p.Proxy.Approval
			}
			if mode == "" {
				mode = p.Approval
			}
			return mode == ApprovalAlways
		}
	}
	// No matching rule — fail closed.
	return true
}

// matchesAnyHost returns true if host matches any of the given host patterns.
// Uses path.Match for glob matching, consistent with command matching.
func matchesAnyHost(host string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, err := path.Match(pattern, host); err == nil && matched {
			return true
		}
	}
	return false
}

// containsSecret returns true if the secret name is in the list.
func containsSecret(secret string, secrets []string) bool {
	for _, s := range secrets {
		if s == secret {
			return true
		}
	}
	return false
}
