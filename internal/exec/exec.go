package exec

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/nokey-ai/nokey/internal/env"
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
	cmd.Env = env.MergeEnvironment(os.Environ(), secrets)

	// Connect standard streams
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Setup signal forwarding channel
	sigChan := make(chan os.Signal, 1)

	// Start the command
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("failed to start command: %w", err)
	}

	// Register signal forwarding after successful start
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer func() { signal.Stop(sigChan); close(sigChan) }()

	// Goroutine to forward signals to the child process
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	// Wait for the command to complete
	err := cmd.Wait()

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
