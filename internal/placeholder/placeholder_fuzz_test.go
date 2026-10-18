package placeholder

import (
	"slices"
	"strings"
	"testing"
)

// FuzzExtract checks that every name Extract reports really appears as a
// placeholder in the input, that the result is sorted and unique, and that
// Resolve accepts the args once each reported name has a value.
func FuzzExtract(f *testing.F) {
	f.Add("curl", "-H", "Authorization: Bearer ${{NOKEY:API_TOKEN}}")
	f.Add("${{NOKEY:CMD}}", "${{NOKEY:A}}${{NOKEY:B}}", "${{NOKEY:A}}")
	f.Add("echo", "${{NOKEY:}}", "${{NOKEY:a.b-c_d}}")
	f.Add("echo", "${{NOKEY:${{NOKEY:INNER}}}}", "$${{NOKEY:X}}}")
	f.Add("", "${{nokey:lower}}", "${NOKEY:SINGLE}")

	f.Fuzz(func(t *testing.T, command, arg1, arg2 string) {
		args := []string{arg1, arg2}
		names := Extract(command, args)

		if !slices.IsSorted(names) {
			t.Fatalf("names not sorted: %q", names)
		}
		if len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Fatalf("names not unique: %q", names)
		}

		all := command + "\x00" + strings.Join(args, "\x00")
		secrets := make(map[string]string, len(names))
		for _, name := range names {
			if name == "" {
				t.Fatalf("empty name extracted from %q", all)
			}
			if !strings.Contains(all, "${{NOKEY:"+name+"}}") {
				t.Fatalf("name %q not present as a placeholder in %q", name, all)
			}
			secrets[name] = "v"
		}

		if ContainsPlaceholder(command) || ContainsPlaceholder(arg1) || ContainsPlaceholder(arg2) {
			if len(names) == 0 {
				t.Fatalf("ContainsPlaceholder is true but Extract found nothing in %q", all)
			}
		}

		if _, err := Resolve(args, secrets); err != nil {
			t.Fatalf("Resolve with every extracted name: %v", err)
		}
	})
}
