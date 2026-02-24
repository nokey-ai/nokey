package proxy

import (
	"fmt"
	"path"
	"strings"

	"github.com/nokey-ai/nokey/internal/policy"
)

// MatchRules returns the proxy rules whose host patterns match the given host.
func MatchRules(host string, rules []policy.ProxyRule) []policy.ProxyRule {
	var matched []policy.ProxyRule
	for _, rule := range rules {
		for _, pattern := range rule.Hosts {
			if ok, err := path.Match(pattern, host); err == nil && ok {
				matched = append(matched, rule)
				break
			}
		}
	}
	return matched
}

// ResolveHeaders replaces $SECRET_NAME references in the rule's header values
// with actual secret values. $$ is treated as a literal $. Returns an error if
// a referenced secret is not found in the provided map.
func ResolveHeaders(rule policy.ProxyRule, secrets map[string]string) (map[string]string, error) {
	resolved := make(map[string]string, len(rule.Headers))
	for name, tmpl := range rule.Headers {
		val, err := resolveTemplate(tmpl, secrets)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}
		resolved[name] = val
	}
	return resolved, nil
}

// resolveTemplate replaces $SECRET_NAME references in s with secret values.
func resolveTemplate(s string, secrets map[string]string) (string, error) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// Check for $$
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		// Extract secret name: $([A-Za-z_][A-Za-z0-9_]*)
		j := i + 1
		if j < len(s) && (isLetter(s[j]) || s[j] == '_') {
			j++
			for j < len(s) && (isLetter(s[j]) || isDigit(s[j]) || s[j] == '_') {
				j++
			}
			name := s[i+1 : j]
			val, ok := secrets[name]
			if !ok {
				return "", fmt.Errorf("secret %q not found", name)
			}
			b.WriteString(val)
			i = j
		} else {
			// Bare $ not followed by a valid identifier — keep as-is.
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), nil
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// CollectSecretNames returns a deduplicated list of secret names referenced
// across all provided rules.
func CollectSecretNames(rules []policy.ProxyRule) []string {
	seen := make(map[string]bool)
	var names []string
	for _, rule := range rules {
		for _, name := range rule.Secrets {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}
