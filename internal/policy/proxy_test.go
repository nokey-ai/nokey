package policy

import (
	"os"
	"path/filepath"
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
  approval: always
  rules:
    - hosts: ["api.openai.com"]
      headers:
        Authorization: "Bearer $OPENAI_API_KEY"
    - hosts: ["*.anthropic.com"]
      headers:
        x-api-key: "$ANTHROPIC_API_KEY"
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

func TestProxyRequiresApproval(t *testing.T) {
	tests := []struct {
		name        string
		policy      *Policy
		host        string
		secretNames []string
		want        bool
	}{
		{
			name:        "nil policy never requires approval",
			policy:      nil,
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        false,
		},
		{
			name:        "no proxy section never requires approval",
			policy:      &Policy{},
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        false,
		},
		{
			name:        "empty secrets never requires approval",
			policy:      &Policy{Proxy: &ProxyPolicy{Approval: ApprovalAlways}},
			host:        "api.example.com",
			secretNames: []string{},
			want:        false,
		},
		{
			name: "proxy global always — approval needed",
			policy: &Policy{
				Proxy: &ProxyPolicy{
					Approval: ApprovalAlways,
					Rules: []ProxyRule{
						{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}},
					},
				},
			},
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        true,
		},
		{
			name: "proxy global never — no approval",
			policy: &Policy{
				Proxy: &ProxyPolicy{
					Approval: ApprovalNever,
					Rules: []ProxyRule{
						{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}},
					},
				},
			},
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        false,
		},
		{
			name: "per-rule never overrides proxy always",
			policy: &Policy{
				Proxy: &ProxyPolicy{
					Approval: ApprovalAlways,
					Rules: []ProxyRule{
						{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}, Approval: ApprovalNever},
					},
				},
			},
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        false,
		},
		{
			name: "per-rule always overrides proxy never",
			policy: &Policy{
				Proxy: &ProxyPolicy{
					Approval: ApprovalNever,
					Rules: []ProxyRule{
						{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}, Approval: ApprovalAlways},
					},
				},
			},
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        true,
		},
		{
			name: "falls back to global policy approval",
			policy: &Policy{
				Approval: ApprovalAlways,
				Proxy: &ProxyPolicy{
					Rules: []ProxyRule{
						{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}},
					},
				},
			},
			host:        "api.example.com",
			secretNames: []string{"TOKEN"},
			want:        true,
		},
		{
			name: "no matching rule — fail closed",
			policy: &Policy{
				Proxy: &ProxyPolicy{
					Approval: ApprovalNever,
					Rules: []ProxyRule{
						{Hosts: []string{"api.example.com"}, Secrets: []string{"TOKEN"}},
					},
				},
			},
			host:        "other.example.com",
			secretNames: []string{"TOKEN"},
			want:        true,
		},
		{
			name: "wildcard host match",
			policy: &Policy{
				Proxy: &ProxyPolicy{
					Approval: ApprovalNever,
					Rules: []ProxyRule{
						{Hosts: []string{"*.anthropic.com"}, Secrets: []string{"API_KEY"}},
					},
				},
			},
			host:        "api.anthropic.com",
			secretNames: []string{"API_KEY"},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.ProxyRequiresApproval(tt.host, tt.secretNames)
			if got != tt.want {
				t.Errorf("ProxyRequiresApproval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesAnyHost(t *testing.T) {
	tests := []struct {
		host     string
		patterns []string
		want     bool
	}{
		{"api.openai.com", []string{"api.openai.com"}, true},
		{"api.anthropic.com", []string{"*.anthropic.com"}, true},
		{"anthropic.com", []string{"*.anthropic.com"}, false},
		{"api.example.com", []string{"api.openai.com", "api.example.com"}, true},
		{"other.com", []string{"api.openai.com"}, false},
	}

	for _, tt := range tests {
		if got := matchesAnyHost(tt.host, tt.patterns); got != tt.want {
			t.Errorf("matchesAnyHost(%q, %v) = %v, want %v", tt.host, tt.patterns, got, tt.want)
		}
	}
}
