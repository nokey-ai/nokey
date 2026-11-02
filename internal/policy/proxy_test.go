package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyRulesYAMLParsing(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantErr   bool
		wantRules int
	}{
		{
			name: "valid proxy section",
			content: `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
proxy:
  approval: never
  rules:
    - hosts: ["api.openai.com"]
      headers:
        Authorization: "Bearer $OPENAI_API_KEY"
    - hosts: ["*.example.com"]
      headers:
        x-api-key: "$EXAMPLE_API_KEY"
      approval: never
`,
			wantRules: 2,
		},
		{
			name: "no proxy section — backward compatible",
			content: `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`,
			wantRules: -1, // -1 means Proxy is nil
		},
		{
			name: "proxy with multiple headers",
			content: `proxy:
  rules:
    - hosts: ["api.github.com"]
      headers:
        Authorization: "token $GITHUB_TOKEN"
        Accept: "application/vnd.github.v3+json"
`,
			wantRules: 1,
		},
		{
			name:    "proxy rule empty hosts rejected",
			content: "proxy:\n  rules:\n    - hosts: []\n      headers:\n        Authorization: \"Bearer $TOKEN\"\n",
			wantErr: true,
		},
		{
			name:    "proxy rule empty headers rejected",
			content: "proxy:\n  rules:\n    - hosts: [\"api.example.com\"]\n      headers: {}\n",
			wantErr: true,
		},
		{
			name:    "proxy rule no secret references rejected",
			content: "proxy:\n  rules:\n    - hosts: [\"api.example.com\"]\n      headers:\n        Accept: \"application/json\"\n",
			wantErr: true,
		},
		{
			name:    "proxy invalid approval mode rejected",
			content: "proxy:\n  approval: sometimes\n  rules:\n    - hosts: [\"api.example.com\"]\n      headers:\n        Authorization: \"Bearer $TOKEN\"\n",
			wantErr: true,
		},
		{
			name:    "proxy rule invalid approval mode rejected",
			content: "proxy:\n  rules:\n    - hosts: [\"api.example.com\"]\n      headers:\n        Authorization: \"Bearer $TOKEN\"\n      approval: maybe\n",
			wantErr: true,
		},
		{
			name: "escaped dollar not counted as secret",
			content: `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $TOKEN"
        X-Price: "$$100"
`,
			wantRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}

			pol, err := Load(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantRules == -1 {
				if pol.Proxy != nil {
					t.Fatal("expected nil Proxy")
				}
				return
			}

			if pol.Proxy == nil {
				t.Fatal("expected non-nil Proxy")
			}
			if len(pol.Proxy.Rules) != tt.wantRules {
				t.Errorf("got %d proxy rules, want %d", len(pol.Proxy.Rules), tt.wantRules)
			}
		})
	}
}

func TestSecretExtraction(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		wantSecrets []string
	}{
		{
			name:        "single secret",
			headers:     map[string]string{"Authorization": "Bearer $API_KEY"},
			wantSecrets: []string{"API_KEY"},
		},
		{
			name:        "multiple secrets",
			headers:     map[string]string{"Authorization": "Bearer $TOKEN", "X-Api-Key": "$OTHER_KEY"},
			wantSecrets: []string{"TOKEN", "OTHER_KEY"},
		},
		{
			name:        "escaped dollar ignored",
			headers:     map[string]string{"Authorization": "Bearer $TOKEN", "X-Price": "$$100"},
			wantSecrets: []string{"TOKEN"},
		},
		{
			name:        "deduped secrets",
			headers:     map[string]string{"Authorization": "Bearer $TOKEN", "X-Token": "$TOKEN"},
			wantSecrets: []string{"TOKEN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp := &ProxyPolicy{
				Rules: []ProxyRule{
					{Hosts: []string{"example.com"}, Headers: tt.headers},
				},
			}
			if err := ValidateProxyRules(pp); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := pp.Rules[0].Secrets
			if len(got) != len(tt.wantSecrets) {
				t.Fatalf("got %d secrets %v, want %d %v", len(got), got, len(tt.wantSecrets), tt.wantSecrets)
			}
			for _, want := range tt.wantSecrets {
				found := false
				for _, s := range got {
					if s == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing expected secret %q in %v", want, got)
				}
			}
		})
	}
}

// The proxy cannot prompt, so approval: always is refused when the policy
// loads instead of silently denying every request at run time. The
// top-level approval mode does not reach proxy rules.
func TestValidateProxyRules_RejectsAlways(t *testing.T) {
	rule := func(mode ApprovalMode) ProxyRule {
		return ProxyRule{Hosts: []string{"api.example.com"}, Headers: map[string]string{"X": "$TOKEN"}, Approval: mode}
	}
	tests := []struct {
		name    string
		pp      *ProxyPolicy
		wantErr string
	}{
		{"proxy global always", &ProxyPolicy{Approval: ApprovalAlways, Rules: []ProxyRule{rule("")}}, "proxy global: approval: always is not supported"},
		{"rule always", &ProxyPolicy{Rules: []ProxyRule{rule(ApprovalAlways)}}, "proxy rule 0: approval: always is not supported"},
		{"rule never", &ProxyPolicy{Rules: []ProxyRule{rule(ApprovalNever)}}, ""},
		{"unset", &ProxyPolicy{Rules: []ProxyRule{rule("")}}, ""},
		{"proxy global never", &ProxyPolicy{Approval: ApprovalNever, Rules: []ProxyRule{rule("")}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyRules(tt.pp)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_TopLevelAlwaysDoesNotReachProxyRules(t *testing.T) {
	dir := t.TempDir()
	yaml := "approval: always\nrules:\n  - commands: [\"*\"]\n    secrets: [\"*\"]\nproxy:\n  rules:\n    - hosts: [\"api.example.com\"]\n      headers:\n        X: \"$TOKEN\"\n"
	if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("a top-level approval: always must not invalidate proxy rules: %v", err)
	}
}

func TestProxyRuleMatchesHost(t *testing.T) {
	tests := []struct {
		host     string
		patterns []string
		want     bool
	}{
		{"api.openai.com", []string{"api.openai.com"}, true},
		{"api.example.com", []string{"*.example.com"}, true},
		{"example.com", []string{"*.example.com"}, false},
		{"api.example.com", []string{"api.openai.com", "api.example.com"}, true},
		{"other.com", []string{"api.openai.com"}, false},
	}

	for _, tt := range tests {
		if got := (ProxyRule{Hosts: tt.patterns}).MatchesHost(tt.host); got != tt.want {
			t.Errorf("MatchesHost(%q) with hosts %v = %v, want %v", tt.host, tt.patterns, got, tt.want)
		}
	}
}

func TestProxyRules(t *testing.T) {
	// nil policy
	var p *Policy
	if rules := p.ProxyRules(); rules != nil {
		t.Errorf("nil Policy.ProxyRules() = %v, want nil", rules)
	}

	// policy with no proxy section
	p = &Policy{}
	if rules := p.ProxyRules(); rules != nil {
		t.Errorf("Policy with no proxy.ProxyRules() = %v, want nil", rules)
	}

	// policy with proxy rules
	p = &Policy{
		Proxy: &ProxyPolicy{
			Rules: []ProxyRule{
				{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}},
			},
		},
	}
	rules := p.ProxyRules()
	if len(rules) != 1 {
		t.Errorf("ProxyRules() = %d rules, want 1", len(rules))
	}
}
