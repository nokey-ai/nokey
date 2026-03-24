//go:build windows

package redact

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"

	"github.com/nokey-ai/nokey/internal/env"
)

// Run executes a command with pipe-based output redaction.
// Any occurrence of a secret value in stdout/stderr will be replaced with [REDACTED:KEY_NAME].
// Optional extraEnv entries (e.g. proxy vars) are appended after the merge.
func Run(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
	if command == "" {
		return 1, fmt.Errorf("command cannot be empty")
	}

	cmd := exec.Command(command, args...)
	cmd.Env = append(env.MergeEnvironment(os.Environ(), secrets), extraEnv...)
	cmd.Stdin = os.Stdin

	// Capture stdout and stderr via pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 1, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("failed to start command: %w", err)
	}

	// Setup signal forwarding
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()
	defer func() { signal.Stop(sigChan); close(sigChan) }()

	// Build redactor
	redactor := newRedactor(secrets)
	defer redactor.Clear()

	// Copy stdout with redaction
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(os.Stdout, &redactingReader{reader: stdoutPipe, redactor: redactor})
		close(done)
	}()
	// Copy stderr with redaction
	_, _ = io.Copy(os.Stderr, &redactingReader{reader: stderrPipe, redactor: redactor})
	<-done

	err = cmd.Wait()

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
