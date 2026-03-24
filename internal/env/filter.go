package env

import (
	"fmt"
	"strings"
)

// FilterSecrets filters the secrets map based on only and except lists.
// If both are specified, an error is returned.
func FilterSecrets(allSecrets map[string]string, only, except string) (map[string]string, error) {
	if only != "" && except != "" {
		return nil, fmt.Errorf("cannot use both --only and --except flags")
	}

	if only != "" {
		onlyList := ParseCommaSeparated(only)
		filtered := make(map[string]string)
		for _, key := range onlyList {
			if value, ok := allSecrets[key]; ok {
				filtered[key] = value
			} else {
				return nil, fmt.Errorf("secret not found: %s", key)
			}
		}
		return filtered, nil
	}

	if except != "" {
		exceptList := ParseCommaSeparated(except)
		exceptMap := make(map[string]bool)
		for _, key := range exceptList {
			exceptMap[key] = true
		}

		filtered := make(map[string]string)
		for key, value := range allSecrets {
			if !exceptMap[key] {
				filtered[key] = value
			}
		}
		return filtered, nil
	}

	return allSecrets, nil
}

// ParseCommaSeparated parses a comma-separated string into a slice of trimmed strings.
func ParseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
