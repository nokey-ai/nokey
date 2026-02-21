package env

import "fmt"

// MergeEnvironment merges secrets into the current environment.
// Secrets take precedence over existing environment variables.
func MergeEnvironment(currentEnv []string, secrets map[string]string) []string {
	env := make([]string, 0, len(currentEnv)+len(secrets))

	// Create a map to track which keys we've seen from secrets
	secretKeys := make(map[string]bool, len(secrets))
	for key := range secrets {
		secretKeys[key] = true
	}

	// Add current env vars, skipping any that will be overridden by secrets
	for _, envVar := range currentEnv {
		key := GetEnvKey(envVar)
		if !secretKeys[key] {
			env = append(env, envVar)
		}
	}

	// Add secrets
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// GetEnvKey extracts the key from an environment variable string (KEY=value)
func GetEnvKey(envVar string) string {
	for i := 0; i < len(envVar); i++ {
		if envVar[i] == '=' {
			return envVar[:i]
		}
	}
	return envVar
}
