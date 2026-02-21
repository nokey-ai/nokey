package redact

import (
	"bytes"
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

// Run executes a command with PTY output redaction
// Any occurrence of a secret value in stdout/stderr will be replaced with [REDACTED:KEY_NAME]
func Run(command string, args []string, secrets map[string]string) (int, error) {
	if command == "" {
		return 1, fmt.Errorf("command cannot be empty")
	}

	// Create the command
	cmd := exec.Command(command, args...)

	// Merge secrets into environment
	cmd.Env = env.MergeEnvironment(os.Environ(), secrets)

	// Start command with a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return 1, fmt.Errorf("failed to start command with PTY: %w", err)
	}
	defer ptmx.Close()

	// Handle terminal resize signals
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			_ = pty.InheritSize(os.Stdin, ptmx)
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

// redactor handles the actual redaction logic
type redactor struct {
	replacements map[string]string // value -> replacement
}

func newRedactor(secrets map[string]string) *redactor {
	r := &redactor{
		replacements: make(map[string]string),
	}

	for key, value := range secrets {
		// Only redact non-empty values
		if value != "" {
			r.replacements[value] = fmt.Sprintf("[REDACTED:%s]", key)
		}
	}

	return r
}

// redact replaces secret values in the data
func (r *redactor) redact(data []byte) []byte {
	result := data
	for secret, replacement := range r.replacements {
		result = bytes.ReplaceAll(result, []byte(secret), []byte(replacement))
	}
	return result
}

// redactingReader wraps an io.Reader and redacts secrets from the data
type redactingReader struct {
	reader   io.Reader
	redactor *redactor
}

func (r *redactingReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		redacted := r.redactor.redact(p[:n])
		n = copy(p, redacted)
	}
	return n, err
}
