package proxy

import (
	"testing"

	"github.com/nokey-ai/nokey/internal/policy"
)

// FuzzResolveTemplateMatchesPolicy checks that resolveTemplate looks up
// exactly the secrets policy validation extracted from the same header
// value. If the two parsers disagree, a rule can inject a secret the policy
// never recorded for approval, or fail on one it did.
func FuzzResolveTemplateMatchesPolicy(f *testing.F) {
	f.Add("Bearer $API_TOKEN")
	f.Add("$A$B $_c1 $$D $$$E")
	f.Add("$ $1 $- trailing $")
	f.Add("price: $$5 for $ITEM_9x")
	f.Add("$été $Z\x00$Y")

	f.Fuzz(func(t *testing.T, header string) {
		pp := &policy.ProxyPolicy{Rules: []policy.ProxyRule{{
			Hosts:   []string{"example.com"},
			Headers: map[string]string{"X": header},
		}}}
		var names []string
		if err := policy.ValidateProxyRules(pp); err == nil {
			names = pp.Rules[0].Secrets
		}

		secrets := make(map[string]string, len(names))
		for _, name := range names {
			secrets[name] = "v"
		}
		if _, err := resolveTemplate(header, secrets); err != nil {
			t.Fatalf("resolveTemplate needs a secret policy did not extract from %q (policy saw %q): %v", header, names, err)
		}

		// Every extracted name must actually be looked up.
		for _, name := range names {
			without := make(map[string]string, len(secrets))
			for k, v := range secrets {
				if k != name {
					without[k] = v
				}
			}
			if _, err := resolveTemplate(header, without); err == nil {
				t.Fatalf("policy extracted %q from %q but resolveTemplate never used it", name, header)
			}
		}
	})
}
