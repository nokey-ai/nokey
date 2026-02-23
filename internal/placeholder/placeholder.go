package placeholder

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var placeholderRe = regexp.MustCompile(`\$\{\{NOKEY:([A-Za-z0-9_-]+)\}\}`)

// ContainsPlaceholder returns true if s contains any ${{NOKEY:...}} placeholder.
func ContainsPlaceholder(s string) bool {
	return placeholderRe.MatchString(s)
}

// Extract scans command and args for ${{NOKEY:SECRET_NAME}} placeholders and
// returns the unique secret names in sorted order.
func Extract(command string, args []string) []string {
	seen := make(map[string]struct{})

	for _, m := range placeholderRe.FindAllStringSubmatch(command, -1) {
		seen[m[1]] = struct{}{}
	}
	for _, arg := range args {
		for _, m := range placeholderRe.FindAllStringSubmatch(arg, -1) {
			seen[m[1]] = struct{}{}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Resolve replaces all ${{NOKEY:SECRET_NAME}} placeholders in args with the
// corresponding value from secrets. It returns an error if any referenced
// secret is missing from the map.
func Resolve(args []string, secrets map[string]string) ([]string, error) {
	resolved := make([]string, len(args))
	for i, arg := range args {
		var missing []string
		result := placeholderRe.ReplaceAllStringFunc(arg, func(match string) string {
			name := placeholderRe.FindStringSubmatch(match)[1]
			val, ok := secrets[name]
			if !ok {
				missing = append(missing, name)
				return match
			}
			return val
		})
		if len(missing) > 0 {
			return nil, fmt.Errorf("secrets not found: %s", strings.Join(missing, ", "))
		}
		resolved[i] = result
	}
	return resolved, nil
}
