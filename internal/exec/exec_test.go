package exec

import (
	"testing"
)

func TestMergeEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		currentEnv  []string
		secrets     map[string]string
		expectKeys  map[string]string
	}{
		{
			name:       "Empty secrets",
			currentEnv: []string{"PATH=/usr/bin", "HOME=/home/user"},
			secrets:    map[string]string{},
			expectKeys: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
		},
		{
			name:       "Add new secrets",
			currentEnv: []string{"PATH=/usr/bin"},
			secrets:    map[string]string{"API_KEY": "secret123"},
			expectKeys: map[string]string{
				"PATH":    "/usr/bin",
				"API_KEY": "secret123",
			},
		},
		{
			name:       "Override existing env var",
			currentEnv: []string{"API_KEY=old_value", "PATH=/usr/bin"},
			secrets:    map[string]string{"API_KEY": "new_value"},
			expectKeys: map[string]string{
				"PATH":    "/usr/bin",
				"API_KEY": "new_value",
			},
		},
		{
			name:       "Multiple secrets",
			currentEnv: []string{"PATH=/usr/bin"},
			secrets: map[string]string{
				"OPENAI_API_KEY": "sk-123",
				"GITHUB_TOKEN":   "ghp_456",
			},
			expectKeys: map[string]string{
				"PATH":            "/usr/bin",
				"OPENAI_API_KEY":  "sk-123",
				"GITHUB_TOKEN":    "ghp_456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeEnvironment(tt.currentEnv, tt.secrets)

			// Convert result to map for easier testing
			resultMap := make(map[string]string)
			for _, envVar := range result {
				key := getEnvKey(envVar)
				value := envVar[len(key)+1:] // Skip the "=" sign
				resultMap[key] = value
			}

			// Check all expected keys are present with correct values
			for key, expectedValue := range tt.expectKeys {
				if value, ok := resultMap[key]; !ok {
					t.Errorf("Expected key %s not found in result", key)
				} else if value != expectedValue {
					t.Errorf("Key %s: expected value %q, got %q", key, expectedValue, value)
				}
			}

			// Check no unexpected keys
			if len(resultMap) != len(tt.expectKeys) {
				t.Errorf("Expected %d keys, got %d", len(tt.expectKeys), len(resultMap))
			}
		})
	}
}

func TestGetEnvKey(t *testing.T) {
	tests := []struct {
		envVar      string
		expectedKey string
	}{
		{"PATH=/usr/bin", "PATH"},
		{"HOME=/home/user", "HOME"},
		{"API_KEY=secret", "API_KEY"},
		{"EMPTY=", "EMPTY"},
		{"NO_EQUALS", "NO_EQUALS"},
	}

	for _, tt := range tests {
		t.Run(tt.envVar, func(t *testing.T) {
			key := getEnvKey(tt.envVar)
			if key != tt.expectedKey {
				t.Errorf("Expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
