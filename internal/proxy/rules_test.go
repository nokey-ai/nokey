package proxy

import (
	"testing"

	"github.com/nokey-ai/nokey/internal/policy"
)

func TestMatchRules(t *testing.T) {
	rules := []policy.ProxyRule{
		{Hosts: []string{"api.openai.com"}, Headers: map[string]string{"Authorization": "Bearer $TOKEN"}},
		{Hosts: []string{"*.anthropic.com"}, Headers: map[string]string{"x-api-key": "$KEY"}},
		{Hosts: []string{"api.github.com"}, Headers: map[string]string{"Authorization": "token $GH"}},
	}

	tests := []struct {
		host      string
		wantCount int
	}{
		{"api.openai.com", 1},
		{"api.anthropic.com", 1},
		{"other.anthropic.com", 1},
		{"anthropic.com", 0}, // * requires at least one char
		{"api.github.com", 1},
		{"unknown.example.com", 0},
	}

	for _, tt := range tests {
		matched := MatchRules(tt.host, rules)
		if len(matched) != tt.wantCount {
			t.Errorf("MatchRules(%q) = %d rules, want %d", tt.host, len(matched), tt.wantCount)
		}
	}
}

func TestResolveHeaders(t *testing.T) {
	secrets := map[string]string{
		"TOKEN":   "sk-123",
		"API_KEY": "key-456",
	}

	tests := []struct {
		name    string
		rule    policy.ProxyRule
		want    map[string]string
		wantErr bool
	}{
		{
			name: "simple substitution",
			rule: policy.ProxyRule{
				Headers: map[string]string{"Authorization": "Bearer $TOKEN"},
			},
			want: map[string]string{"Authorization": "Bearer sk-123"},
		},
		{
			name: "multiple secrets in one header",
			rule: policy.ProxyRule{
				Headers: map[string]string{"X-Auth": "$TOKEN:$API_KEY"},
			},
			want: map[string]string{"X-Auth": "sk-123:key-456"},
		},
		{
			name: "escaped dollar",
			rule: policy.ProxyRule{
				Headers: map[string]string{"X-Price": "$$100"},
			},
			want: map[string]string{"X-Price": "$100"},
		},
		{
			name: "no secrets in header",
			rule: policy.ProxyRule{
				Headers: map[string]string{"Accept": "application/json"},
			},
			want: map[string]string{"Accept": "application/json"},
		},
		{
			name: "missing secret",
			rule: policy.ProxyRule{
				Headers: map[string]string{"Authorization": "Bearer $MISSING"},
			},
			wantErr: true,
		},
		{
			name: "escaped dollar next to secret",
			rule: policy.ProxyRule{
				Headers: map[string]string{"X-Val": "$$$TOKEN"},
			},
			want: map[string]string{"X-Val": "$sk-123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveHeaders(tt.rule, secrets)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, want := range tt.want {
				if got[k] != want {
					t.Errorf("header %q = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

func TestResolveTemplate_BareDollar(t *testing.T) {
	// A bare $ at end of string or followed by a non-identifier char should
	// be kept as-is.
	secrets := map[string]string{"A": "val"}
	tests := []struct {
		input string
		want  string
	}{
		{"price is $", "price is $"},
		{"cost $5", "cost $5"},
		{"$A and $", "val and $"},
	}
	for _, tt := range tests {
		got, err := resolveTemplate(tt.input, secrets)
		if err != nil {
			t.Fatalf("resolveTemplate(%q): %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("resolveTemplate(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCollectSecretNames(t *testing.T) {
	rules := []policy.ProxyRule{
		{Secrets: []string{"TOKEN", "KEY"}},
		{Secrets: []string{"KEY", "OTHER"}},
	}

	names := CollectSecretNames(rules)

	want := map[string]bool{"TOKEN": true, "KEY": true, "OTHER": true}
	if len(names) != len(want) {
		t.Fatalf("got %d names, want %d", len(names), len(want))
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected name %q", n)
		}
	}
}
