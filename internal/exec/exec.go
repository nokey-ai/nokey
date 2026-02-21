package exec

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Run executes a command with the provided secrets merged into the environment
// It handles signal forwarding and returns the exit code of the child process
func Run(command string, args []string, secrets map[string]string) (int, error) {
	if command == "" {
		return 1, fmt.Errorf("command cannot be empty")
	}

	// Create the command
	cmd := exec.Command(command, args...)

	// Merge secrets into environment
	cmd.Env = mergeEnvironment(os.Environ(), secrets)

	// Connect standard streams
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Setup signal forwarding
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start the command
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("failed to start command: %w", err)
	}

	// Goroutine to forward signals to the child process
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				cmd.Process.Signal(sig)
			}
		}
	}()

	// Wait for the command to complete
	err := cmd.Wait()

	// Stop signal forwarding
	signal.Stop(sigChan)
	close(sigChan)

	// Get exit code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			return 1, fmt.Errorf("command execution failed: %w", err)
		}
	}

	return exitCode, nil
}

// mergeEnvironment merges secrets into the current environment
// Secrets take precedence over existing environment variables
func mergeEnvironment(currentEnv []string, secrets map[string]string) []string {
	// Start with current environment
	env := make([]string, 0, len(currentEnv)+len(secrets))

	// Create a map to track which keys we've seen from secrets
	secretKeys := make(map[string]bool, len(secrets))
	for key := range secrets {
		secretKeys[key] = true
	}

	// Add current env vars, skipping any that will be overridden by secrets
	for _, envVar := range currentEnv {
		// Parse env var to get key
		key := getEnvKey(envVar)
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

// getEnvKey extracts the key from an environment variable string (KEY=value)
func getEnvKey(envVar string) string {
	for i := 0; i < len(envVar); i++ {
		if envVar[i] == '=' {
			return envVar[:i]
		}
	}
	return envVar
}
