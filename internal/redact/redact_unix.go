//go:build !windows

package redact

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"github.com/nokey-ai/nokey/internal/env"
	"golang.org/x/term"
)

// ptyStartFn is the function used to start a command with a PTY. Overridable for testing.
var ptyStartFn = pty.Start

// ptyInheritSizeFn is the function used to inherit terminal size. Overridable for testing.
var ptyInheritSizeFn = pty.InheritSize

// Run executes a command with PTY output redaction.
// Any occurrence of a secret value in stdout/stderr will be replaced with [REDACTED:KEY_NAME].
// Optional extraEnv entries (e.g. proxy vars) are appended after the merge.
func Run(command string, args []string, secrets map[string]string, extraEnv ...string) (int, error) {
	if command == "" {
		return 1, fmt.Errorf("command cannot be empty")
	}

	// Create the command
	cmd := exec.Command(command, args...)

	// Merge secrets into environment
	cmd.Env = append(env.MergeEnvironment(os.Environ(), secrets), extraEnv...)

	// Start command with a PTY
	ptmx, err := ptyStartFn(cmd)
	if err != nil {
		return 1, fmt.Errorf("failed to start command with PTY: %w", err)
	}
	defer ptmx.Close()

	// Handle terminal resize signals
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			_ = ptyInheritSizeFn(os.Stdin, ptmx)
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize
	defer func() { signal.Stop(ch); close(ch) }()

	// Set stdin to raw mode if it's a terminal
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		// Not a terminal, that's okay
		oldState = nil
	}
	if oldState != nil {
		defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	}

	// Setup signal forwarding
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
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

	// Copy stdin to PTY with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
			return
		default:
			_, _ = io.Copy(ptmx, os.Stdin)
		}
	}()

	// Copy PTY output to stdout with redaction
	_, _ = io.Copy(os.Stdout, &redactingReader{
		reader:   ptmx,
		redactor: redactor,
	})

	// Wait for command to complete
	err = cmd.Wait()

	// Cancel stdin copy goroutine
	cancel()

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
