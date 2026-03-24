//go:build !windows

package redact

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// withMockPTY replaces ptyStartFn and ptyInheritSizeFn with pipe-based
// implementations so Run() can be tested without a real PTY.
func withMockPTY(t *testing.T) {
	t.Helper()
	oldStart := ptyStartFn
	oldInherit := ptyInheritSizeFn
	t.Cleanup(func() {
		ptyStartFn = oldStart
		ptyInheritSizeFn = oldInherit
	})

	ptyStartFn = func(cmd *exec.Cmd) (*os.File, error) {
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		cmd.Stdout = pw
		cmd.Stderr = pw
		if err := cmd.Start(); err != nil {
			pr.Close()
			pw.Close()
			return nil, err
		}
		pw.Close()
		return pr, nil
	}
	ptyInheritSizeFn = func(_, _ *os.File) error { return nil }
}

// captureRun executes Run() with mock PTY, redirected stdin/stdout, and returns the captured output.
func captureRun(t *testing.T, command string, args []string, secrets map[string]string, extraEnv ...string) (output string, exitCode int, err error) {
	t.Helper()
	withMockPTY(t)

	oldStdout := os.Stdout
	outR, outW, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe: %v", pipeErr)
	}
	os.Stdout = outW

	oldStdin := os.Stdin
	devnull, devErr := os.Open(os.DevNull)
	if devErr != nil {
		t.Fatalf("os.Open(/dev/null): %v", devErr)
	}
	os.Stdin = devnull

	defer func() {
		os.Stdout = oldStdout
		os.Stdin = oldStdin
		devnull.Close()
	}()

	exitCode, err = Run(command, args, secrets, extraEnv...)

	outW.Close()
	var buf bytes.Buffer
	io.Copy(&buf, outR)
	outR.Close()

	return buf.String(), exitCode, err
}

func TestRun_EmptyCommand(t *testing.T) {
	exitCode, err := Run("", nil, nil)
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
	if err == nil || !strings.Contains(err.Error(), "command cannot be empty") {
		t.Errorf("error = %v, want 'command cannot be empty'", err)
	}
}

func TestRun_PTYStartError(t *testing.T) {
	old := ptyStartFn
	defer func() { ptyStartFn = old }()
	ptyStartFn = func(_ *exec.Cmd) (*os.File, error) {
		return nil, fmt.Errorf("mock pty error")
	}

	exitCode, err := Run("echo", []string{"hello"}, nil)
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
	if err == nil || !strings.Contains(err.Error(), "failed to start command with PTY") {
		t.Errorf("error = %v, want 'failed to start command with PTY'", err)
	}
}

func TestRun_BasicExecution(t *testing.T) {
	output, exitCode, err := captureRun(t, "echo", []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "hello") {
		t.Errorf("output should contain 'hello', got: %q", output)
	}
}

func TestRun_Redaction(t *testing.T) {
	secrets := map[string]string{"API_KEY": "supersecretvalue123"}
	output, exitCode, err := captureRun(t, "echo", []string{"supersecretvalue123"}, secrets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if strings.Contains(output, "supersecretvalue123") {
		t.Errorf("output should not contain secret, got: %q", output)
	}
	if !strings.Contains(output, "[REDACTED:API_KEY]") {
		t.Errorf("output should contain [REDACTED:API_KEY], got: %q", output)
	}
}

func TestRun_NonZeroExitCode(t *testing.T) {
	_, exitCode, err := captureRun(t, "sh", []string{"-c", "exit 42"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exit code = %d, want 42", exitCode)
	}
}

func TestRun_ExtraEnv(t *testing.T) {
	output, exitCode, err := captureRun(t, "sh", []string{"-c", "echo $NOKEY_TEST_EXTRA"}, nil, "NOKEY_TEST_EXTRA=injected")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "injected") {
		t.Errorf("output should contain 'injected', got: %q", output)
	}
}

func TestRun_NoSecrets(t *testing.T) {
	output, exitCode, err := captureRun(t, "echo", []string{"plaintext"}, map[string]string{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "plaintext") {
		t.Errorf("output should contain 'plaintext', got: %q", output)
	}
}
