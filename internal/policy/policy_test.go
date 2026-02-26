package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name      string
		content   string // empty means no file
		wantNil   bool
		wantErr   bool
		wantRules int
	}{
		{
			name:    "no file returns nil policy",
			wantNil: true,
		},
		{
			name: "valid policy",
			content: `rules:
  - commands: ["gh", "git"]
    secrets: ["GITHUB_TOKEN"]
  - commands: ["aws"]
    secrets: ["AWS_*"]
`,
			wantRules: 2,
		},
		{
			name: "empty rules list is valid",
			content: `rules: []
`,
			wantRules: 0,
		},
		{
			name:    "malformed YAML",
			content: `rules: [invalid yaml`,
			wantErr: true,
		},
		{
			name: "empty commands rejected",
			content: `rules:
  - commands: []
    secrets: ["TOKEN"]
`,
			wantErr: true,
		},
		{
			name: "empty secrets rejected",
			content: `rules:
  - commands: ["gh"]
    secrets: []
`,
			wantErr: true,
		},
		{
			name: "valid global approval always",
			content: `approval: always
rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`,
			wantRules: 1,
		},
		{
			name: "valid global approval never",
			content: `approval: never
rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`,
			wantRules: 1,
		},
		{
			name: "valid per-rule approval",
			content: `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
    approval: always
`,
			wantRules: 1,
		},
		{
			name: "missing approval is backward compatible",
			content: `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`,
			wantRules: 1,
		},
		{
			name: "invalid global approval rejected",
			content: `approval: sometimes
rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`,
			wantErr: true,
		},
		{
			name: "invalid per-rule approval rejected",
			content: `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
    approval: maybe
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.content != "" {
				if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(tt.content), 0600); err != nil {
					t.Fatal(err)
				}
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

			if tt.wantNil {
				if pol != nil {
					t.Fatal("expected nil policy")
				}
				return
			}

			if pol == nil {
				t.Fatal("expected non-nil policy")
			}
			if len(pol.Rules) != tt.wantRules {
				t.Errorf("got %d rules, want %d", len(pol.Rules), tt.wantRules)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name        string
		policy      *Policy
		command     string
		secretNames []string
		wantErr     bool
		wantSecret  string // expected denied secret, if any
	}{
		{
			name:        "nil policy allows everything",
			policy:      nil,
			command:     "anything",
			secretNames: []string{"ANY_SECRET"},
		},
		{
			name:        "empty secrets always allowed",
			policy:      &Policy{Rules: []Rule{}},
			command:     "anything",
			secretNames: []string{},
		},
		{
			name: "exact match allowed",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
		},
		{
			name: "glob secret pattern",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"aws"}, Secrets: []string{"AWS_*"}},
			}},
			command:     "aws",
			secretNames: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		},
		{
			name: "wildcard allows all secrets",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"curl"}, Secrets: []string{"*"}},
			}},
			command:     "curl",
			secretNames: []string{"ANYTHING", "ELSE"},
		},
		{
			name: "command not in any rule",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "curl",
			secretNames: []string{"GITHUB_TOKEN"},
			wantErr:     true,
			wantSecret:  "GITHUB_TOKEN",
		},
		{
			name: "secret not in any rule",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "gh",
			secretNames: []string{"AWS_KEY"},
			wantErr:     true,
			wantSecret:  "AWS_KEY",
		},
		{
			name: "partial match denies on missing secret",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN", "AWS_KEY"},
			wantErr:     true,
			wantSecret:  "AWS_KEY",
		},
		{
			name: "full path stripped to base",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "/usr/local/bin/gh",
			secretNames: []string{"GITHUB_TOKEN"},
		},
		{
			name: "command glob pattern",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"git*"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "git-lfs",
			secretNames: []string{"GITHUB_TOKEN"},
		},
		{
			name:        "empty rules deny all secrets",
			policy:      &Policy{Rules: []Rule{}},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			wantErr:     true,
			wantSecret:  "GITHUB_TOKEN",
		},
		{
			name: "multiple rules checked",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
				{Commands: []string{"aws"}, Secrets: []string{"AWS_*"}},
			}},
			command:     "aws",
			secretNames: []string{"AWS_ACCESS_KEY_ID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Check(tt.command, tt.secretNames)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				denial, ok := err.(*Denial)
				if !ok {
					t.Fatalf("expected *Denial, got %T", err)
				}
				if denial.Secret != tt.wantSecret {
					t.Errorf("denied secret = %q, want %q", denial.Secret, tt.wantSecret)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDenialError(t *testing.T) {
	d := &Denial{Command: "gh", Secret: "GITHUB_TOKEN"}
	want := `policy denied: command "gh" is not allowed to access secret "GITHUB_TOKEN"`
	if got := d.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRequiresApproval(t *testing.T) {
	tests := []struct {
		name        string
		policy      *Policy
		command     string
		secretNames []string
		want        bool
	}{
		{
			name:        "nil policy never requires approval",
			policy:      nil,
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name:        "empty secrets never requires approval",
			policy:      &Policy{Approval: ApprovalAlways},
			command:     "gh",
			secretNames: []string{},
			want:        false,
		},
		{
			name: "global never — no approval needed",
			policy: &Policy{
				Approval: ApprovalNever,
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
				},
			},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name: "global always — approval needed",
			policy: &Policy{
				Approval: ApprovalAlways,
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
				},
			},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        true,
		},
		{
			name: "per-rule override: rule never overrides global always",
			policy: &Policy{
				Approval: ApprovalAlways,
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}, Approval: ApprovalNever},
				},
			},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name: "per-rule override: rule always overrides global never",
			policy: &Policy{
				Approval: ApprovalNever,
				Rules: []Rule{
					{Commands: []string{"curl"}, Secrets: []string{"*"}, Approval: ApprovalAlways},
				},
			},
			command:     "curl",
			secretNames: []string{"API_KEY"},
			want:        true,
		},
		{
			name: "mixed rules: one needs approval, one does not",
			policy: &Policy{
				Approval: ApprovalAlways,
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}, Approval: ApprovalNever},
					{Commands: []string{"gh"}, Secrets: []string{"DEPLOY_KEY"}},
				},
			},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN", "DEPLOY_KEY"},
			want:        true,
		},
		{
			name: "no matching rule — fail closed",
			policy: &Policy{
				Approval: ApprovalNever,
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
				},
			},
			command:     "curl",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        true,
		},
		{
			name: "global default empty — treated as never",
			policy: &Policy{
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
				},
			},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name: "full path stripped to base",
			policy: &Policy{
				Approval: ApprovalAlways,
				Rules: []Rule{
					{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
				},
			},
			command:     "/usr/local/bin/gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.RequiresApproval(tt.command, tt.secretNames)
			if got != tt.want {
				t.Errorf("RequiresApproval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequiresToken(t *testing.T) {
	tests := []struct {
		name        string
		policy      *Policy
		command     string
		secretNames []string
		want        bool
	}{
		{
			name:        "nil policy never requires token",
			policy:      nil,
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name:        "empty secrets never requires token",
			policy:      &Policy{Rules: []Rule{{Commands: []string{"gh"}, Secrets: []string{"*"}, TokenRequired: true}}},
			command:     "gh",
			secretNames: []string{},
			want:        false,
		},
		{
			name: "matching rule with token_required true",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"nokey:integration:github"}, Secrets: []string{"GITHUB_TOKEN"}, TokenRequired: true},
			}},
			command:     "nokey:integration:github",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        true,
		},
		{
			name: "matching rule without token_required",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}},
			}},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name: "no matching rule — backward compatible false",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}, TokenRequired: true},
			}},
			command:     "curl",
			secretNames: []string{"GITHUB_TOKEN"},
			want:        false,
		},
		{
			name: "mixed secrets: one requires token, one does not",
			policy: &Policy{Rules: []Rule{
				{Commands: []string{"gh"}, Secrets: []string{"GITHUB_TOKEN"}, TokenRequired: true},
				{Commands: []string{"gh"}, Secrets: []string{"DEPLOY_KEY"}},
			}},
			command:     "gh",
			secretNames: []string{"GITHUB_TOKEN", "DEPLOY_KEY"},
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.RequiresToken(tt.command, tt.secretNames)
			if got != tt.want {
				t.Errorf("RequiresToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		patterns []string
		want     bool
	}{
		{"exact match", "gh", []string{"gh"}, true},
		{"glob star", "AWS_KEY", []string{"AWS_*"}, true},
		{"wildcard", "anything", []string{"*"}, true},
		{"no match", "curl", []string{"gh", "git"}, false},
		{"malformed pattern treated as no match", "value", []string{"["}, false},
		{"character class", "git", []string{"gi[st]"}, true},
		{"question mark", "gh", []string{"g?"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAny(tt.value, tt.patterns); got != tt.want {
				t.Errorf("matchesAny(%q, %v) = %v, want %v", tt.value, tt.patterns, got, tt.want)
			}
		})
	}
}
