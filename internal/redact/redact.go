package redact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/nokey-ai/nokey/internal/env"
	"github.com/nokey-ai/nokey/internal/sensitive"
	"golang.org/x/term"
)

// minSecretLenForVariants is the minimum secret length to generate encoding
// variants. Shorter secrets produce too many false positives.
const minSecretLenForVariants = 8

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

// redactor handles the actual redaction logic
type redactor struct {
	replacements map[string]string // value -> replacement
	sortedKeys   []string          // longest first for greedy matching
}

func newRedactor(secrets map[string]string) *redactor {
	r := &redactor{
		replacements: make(map[string]string),
	}

	for key, value := range secrets {
		if value == "" {
			continue
		}
		label := fmt.Sprintf("[REDACTED:%s]", key)
		r.replacements[value] = label

		if len(value) < minSecretLenForVariants {
			continue
		}

		// Generate encoding variants, all mapping to the same label.
		variants := encodingVariants(value)
		for _, v := range variants {
			if _, exists := r.replacements[v]; !exists {
				r.replacements[v] = label
			}
		}
	}

	// Precompute sorted keys (longest first) so longer matches win.
	r.sortedKeys = make([]string, 0, len(r.replacements))
	for k := range r.replacements {
		r.sortedKeys = append(r.sortedKeys, k)
	}
	sort.Slice(r.sortedKeys, func(i, j int) bool {
		return len(r.sortedKeys[i]) > len(r.sortedKeys[j])
	})

	return r
}

// encodingVariants returns deduplicated encoded forms of value.
func encodingVariants(value string) []string {
	raw := []byte(value)
	seen := make(map[string]bool)
	seen[value] = true // the literal is already in replacements
	var out []string

	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	add(base64.StdEncoding.EncodeToString(raw))
	add(base64.URLEncoding.EncodeToString(raw))
	add(base64.RawStdEncoding.EncodeToString(raw))
	add(base64.RawURLEncoding.EncodeToString(raw))
	add(url.QueryEscape(value))
	hexLower := hex.EncodeToString(raw)
	add(hexLower)
	hexUpper := strings.ToUpper(hexLower)
	add(hexUpper)

	return out
}

// Clear zeros the sensitive data held by the redactor. Keys in the
// replacements map are secret values (and their encoded variants);
// sortedKeys holds the same data.
func (r *redactor) Clear() {
	for k := range r.replacements {
		sensitive.ClearString(k)
		delete(r.replacements, k)
	}
	sensitive.ClearSlice(r.sortedKeys)
	r.sortedKeys = nil
}

// redact replaces secret values in the data
func (r *redactor) redact(data []byte) []byte {
	result := data
	for _, secret := range r.sortedKeys {
		result = bytes.ReplaceAll(result, []byte(secret), []byte(r.replacements[secret]))
	}
	return result
}

// RedactBytes replaces all secret values in data with [REDACTED:KEY_NAME].
// Empty secret values are skipped. Returns nil if data is nil.
func RedactBytes(data []byte, secrets map[string]string) []byte {
	if data == nil {
		return nil
	}
	r := newRedactor(secrets)
	return r.redact(data)
}

// redactingReader wraps an io.Reader and redacts secrets from the data
type redactingReader struct {
	reader   io.Reader
	redactor *redactor
	buf      []byte
}

func (r *redactingReader) Read(p []byte) (n int, err error) {
	// If we have leftover data in our buffer, serve it first
	if len(r.buf) > 0 {
		n = copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	// Otherwise, read new data from the underlying reader
	readBuf := make([]byte, len(p))
	nRead, err := r.reader.Read(readBuf)
	if nRead > 0 {
		redacted := r.redactor.redact(readBuf[:nRead])
		n = copy(p, redacted)

		// If redacted output is larger than p, store the rest in our buffer
		if n < len(redacted) {
			r.buf = append(r.buf, redacted[n:]...)
		}
	}
	return n, err
}
