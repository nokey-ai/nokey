package policy

import (
	"fmt"
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
	Hosts   []string          `yaml:"hosts"`
	Headers map[string]string `yaml:"headers"`
	// Approval may only be "never" or empty: the proxy cannot prompt, and
	// the top-level approval mode does not apply to proxy rules.
	Approval ApprovalMode `yaml:"approval,omitempty"`
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
	if pp.Approval == ApprovalAlways {
		return fmt.Errorf("proxy global: approval: always is not supported — the proxy cannot prompt, so use approval: never or omit it")
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
		if rule.Approval == ApprovalAlways {
			return fmt.Errorf("proxy rule %d: approval: always is not supported — the proxy cannot prompt, so use approval: never or omit it", i)
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

// MatchesHost reports whether host matches any of the rule's host patterns.
// It uses the same glob matching as command and secret patterns, so
// malformed patterns are treated as non-matching.
func (r ProxyRule) MatchesHost(host string) bool {
	return matchesAny(host, r.Hosts)
}
