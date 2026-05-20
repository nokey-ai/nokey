//go:build !windows

package redact

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
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

	// Capture stdin once. The spawned goroutines hold this *os.File for
	// their entire lifetime, so callers (notably tests) can safely swap
	// os.Stdin after Run returns without racing the goroutines.
	stdin := os.Stdin

	// Start command with a PTY
	ptmx, err := ptyStartFn(cmd)
	if err != nil {
		return 1, fmt.Errorf("failed to start command with PTY: %w", err)
	}

	var wg sync.WaitGroup

	// Handle terminal resize signals
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range winchCh {
			_ = ptyInheritSizeFn(stdin, ptmx)
		}
	}()
	winchCh <- syscall.SIGWINCH // Initial resize

	// Set stdin to raw mode if it's a terminal
	oldState, err := term.MakeRaw(int(stdin.Fd()))
	if err != nil {
		// Not a terminal, that's okay
		oldState = nil
	}
	if oldState != nil {
		defer func() { _ = term.Restore(int(stdin.Fd()), oldState) }()
	}

	// Setup signal forwarding
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	// Build redactor
	redactor := newRedactor(secrets)
	defer redactor.Clear()

	// Copy stdin to PTY. The goroutine unblocks when stdin reaches EOF
	// or when ptmx is closed below.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ptmx, stdin)
	}()

	// Copy PTY output to stdout with redaction. Returns when the child
	// closes the slave side (typically when it exits).
	_, _ = io.Copy(os.Stdout, &redactingReader{
		reader:   ptmx,
		redactor: redactor,
	})

	// Wait for command to complete
	err = cmd.Wait()

	// Tear down: close ptmx so the stdin-copy goroutine unblocks, then
	// stop and close the signal channels so the signal goroutines exit.
	// Wait for all spawned goroutines to finish before returning so the
	// caller can safely mutate any state the goroutines were reading.
	_ = ptmx.Close()
	signal.Stop(winchCh)
	close(winchCh)
	signal.Stop(sigChan)
	close(sigChan)
	wg.Wait()

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
