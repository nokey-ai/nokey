package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad writes arbitrary bytes as policies.yaml and loads them. The
// policy file is user-edited, so malformed input must be rejected with an
// error, and anything that loads must be safe to evaluate.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("rules:\n  - commands: [\"curl*\"]\n    secrets: [\"API_*\"]\n    approval: always\n"))
	f.Add([]byte("approval: never\nrules:\n  - commands: [\"[\"]\n    secrets: [\"*\"]\n    token_required: true\n"))
	f.Add([]byte("proxy:\n  rules:\n    - hosts: [\"*.example.com\"]\n      headers:\n        Authorization: \"Bearer $TOKEN $$\"\n"))
	f.Add([]byte("rules: {}\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("unknown_key: 1\nrules: []\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), data, 0o600); err != nil {
			t.Fatal(err)
		}

		pol, err := Load(dir)
		_, strictErr := LoadStrict(dir)
		if strictErr == nil && err != nil {
			t.Fatalf("LoadStrict accepted a policy Load rejects: %v", err)
		}
		if err != nil {
			return
		}

		if pol.Proxy != nil {
			for i, rule := range pol.Proxy.Rules {
				if len(rule.Secrets) == 0 {
					t.Fatalf("proxy rule %d loaded without any secret references", i)
				}
			}
		}

		// Patterns come straight from the file; evaluating them must not panic.
		_ = pol.Check("curl", []string{"API_KEY"})
		_ = pol.RequiresApproval("curl", []string{"API_KEY"})
		_ = pol.RequiresToken("curl", []string{"API_KEY"})
		_ = pol.ProxyRequiresApproval("api.example.com", []string{"TOKEN"})
	})
}
