package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRedactBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		secrets map[string]string
		want    string
	}{
		{
			name:    "basic redaction",
			data:    []byte("my token is sk-abc123"),
			secrets: map[string]string{"API_KEY": "sk-abc123"},
			want:    "my token is [REDACTED:API_KEY]",
		},
		{
			name: "multiple secrets",
			data: []byte("host=db.example.com pass=hunter2"),
			secrets: map[string]string{
				"DB_HOST": "db.example.com",
				"DB_PASS": "hunter2",
			},
			want: "host=[REDACTED:DB_HOST] pass=[REDACTED:DB_PASS]",
		},
		{
			name:    "empty secrets map",
			data:    []byte("nothing to redact"),
			secrets: map[string]string{},
			want:    "nothing to redact",
		},
		{
			name:    "nil secrets map",
			data:    []byte("nothing to redact"),
			secrets: nil,
			want:    "nothing to redact",
		},
		{
			name: "empty values skipped",
			data: []byte("keep this text"),
			secrets: map[string]string{
				"EMPTY":    "",
				"NONEMPTY": "this text",
			},
			want: "keep [REDACTED:NONEMPTY]",
		},
		{
			name:    "nil data returns nil",
			data:    nil,
			secrets: map[string]string{"KEY": "value"},
			want:    "",
		},
		{
			name:    "secret appears multiple times",
			data:    []byte("tok tok tok"),
			secrets: map[string]string{"TOKEN": "tok"},
			want:    "[REDACTED:TOKEN] [REDACTED:TOKEN] [REDACTED:TOKEN]",
		},
		{
			name:    "base64 encoded secret",
			data:    []byte("token=" + base64.StdEncoding.EncodeToString([]byte("my-secret-key-value"))),
			secrets: map[string]string{"API_KEY": "my-secret-key-value"},
			want:    "token=[REDACTED:API_KEY]",
		},
		{
			name:    "url encoded secret",
			data:    []byte("q=" + url.QueryEscape("secret value with spaces")),
			secrets: map[string]string{"PASS": "secret value with spaces"},
			want:    "q=[REDACTED:PASS]",
		},
		{
			name:    "hex encoded secret",
			data:    []byte("h=" + hex.EncodeToString([]byte("my-secret-key-value"))),
			secrets: map[string]string{"API_KEY": "my-secret-key-value"},
			want:    "h=[REDACTED:API_KEY]",
		},
		{
			name:    "short secret skips variants",
			data:    []byte("raw=short b64=" + base64.StdEncoding.EncodeToString([]byte("short"))),
			secrets: map[string]string{"S": "short"},
			want:    "raw=[REDACTED:S] b64=" + base64.StdEncoding.EncodeToString([]byte("short")),
		},
		{
			name: "longest match wins",
			data: []byte("the value is supersecretvalue"),
			secrets: map[string]string{
				"FULL":  "supersecretvalue",
				"SHORT": "secret",
			},
			want: "the value is [REDACTED:FULL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactBytes(tt.data, tt.secrets)
			if tt.data == nil {
				if got != nil {
					t.Errorf("RedactBytes(nil, ...) = %q, want nil", got)
				}
				return
			}
			if string(got) != tt.want {
				t.Errorf("RedactBytes() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- redactingReader ---

func TestRedactingReader_BasicRedaction(t *testing.T) {
	secrets := map[string]string{"KEY": "secret"}
	r := newRedactor(secrets)
	reader := &redactingReader{
		reader:   strings.NewReader("the secret is here"),
		redactor: r,
	}

	buf := make([]byte, 256)
	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "[REDACTED:KEY]") {
		t.Errorf("expected redaction, got: %q", got)
	}
	if strings.Contains(got, "secret") {
		t.Errorf("secret should be redacted, got: %q", got)
	}
}

func TestRedactingReader_BufferOverflow(t *testing.T) {
	// When redacted output is larger than the read buffer, leftover goes to internal buf
	secrets := map[string]string{"K": "x"}
	r := newRedactor(secrets)
	reader := &redactingReader{
		reader:   strings.NewReader("x"), // 1 byte becomes "[REDACTED:K]" (12 bytes)
		redactor: r,
	}

	// Read with a tiny buffer
	small := make([]byte, 5)
	n, err := reader.Read(small)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	part1 := string(small[:n])

	// Read remaining from internal buffer
	rest := make([]byte, 256)
	n2, _ := reader.Read(rest)
	part2 := string(rest[:n2])

	full := part1 + part2
	if full != "[REDACTED:K]" {
		t.Errorf("combined output = %q, want %q", full, "[REDACTED:K]")
	}
}

func TestRedactingReader_NoSecrets(t *testing.T) {
	r := newRedactor(nil)
	reader := &redactingReader{
		reader:   strings.NewReader("plain text"),
		redactor: r,
	}

	buf := make([]byte, 256)
	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "plain text" {
		t.Errorf("got %q, want %q", string(buf[:n]), "plain text")
	}
}

func TestRedactingReader_EOF(t *testing.T) {
	r := newRedactor(nil)
	reader := &redactingReader{
		reader:   strings.NewReader(""),
		redactor: r,
	}

	buf := make([]byte, 256)
	n, err := reader.Read(buf)
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

// --- redactor.Clear ---

func TestRedactor_Clear(t *testing.T) {
	secrets := map[string]string{"KEY": "longersecretvalue"}
	r := newRedactor(secrets)

	if len(r.replacements) == 0 {
		t.Fatal("replacements should not be empty before Clear")
	}
	if len(r.sortedKeys) == 0 {
		t.Fatal("sortedKeys should not be empty before Clear")
	}

	r.Clear()

	if len(r.replacements) != 0 {
		t.Errorf("replacements should be empty after Clear, got %d", len(r.replacements))
	}
	if r.sortedKeys != nil {
		t.Errorf("sortedKeys should be nil after Clear")
	}
}

// --- newRedactor ---

func TestNewRedactor_EmptyValues(t *testing.T) {
	r := newRedactor(map[string]string{"EMPTY": "", "NONEMPTY": "val"})
	// Only NONEMPTY should be in replacements
	if _, ok := r.replacements["val"]; !ok {
		t.Error("non-empty value should be in replacements")
	}
	if _, ok := r.replacements[""]; ok {
		t.Error("empty value should not be in replacements")
	}
}

func TestNewRedactor_LongestFirst(t *testing.T) {
	r := newRedactor(map[string]string{
		"SHORT": "ab",
		"LONG":  "abcdefghij",
	})
	if len(r.sortedKeys) < 2 {
		t.Fatal("expected at least 2 sorted keys")
	}
	// First key should be longer or equal to second
	if len(r.sortedKeys[0]) < len(r.sortedKeys[1]) {
		t.Errorf("sortedKeys should be longest first, got %q before %q", r.sortedKeys[0], r.sortedKeys[1])
	}
}

// --- encodingVariants ---

func TestEncodingVariants_ProducesVariants(t *testing.T) {
	// encodingVariants always produces variants; the min-length check is in newRedactor
	variants := encodingVariants("my-secret-key-value")
	if len(variants) == 0 {
		t.Error("expected encoding variants for long secret")
	}
}

func TestNewRedactor_ShortSecretSkipsVariants(t *testing.T) {
	// Short secrets (< 8 chars) should only have the literal, no encoding variants
	r := newRedactor(map[string]string{"S": "short"})
	// Only the literal "short" → "[REDACTED:S]" should be present
	if len(r.replacements) != 1 {
		t.Errorf("short secret should have 1 replacement, got %d", len(r.replacements))
	}
}

func TestEncodingVariants_Deduplicated(t *testing.T) {
	variants := encodingVariants("my-secret-key-value")
	seen := make(map[string]bool)
	for _, v := range variants {
		if seen[v] {
			t.Errorf("duplicate variant: %q", v)
		}
		seen[v] = true
	}
}

// --- Run ---

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

func TestRedactBytesEncodedVariants(t *testing.T) {
	secret := "my-super-secret-api-key-12345"
	secrets := map[string]string{"KEY": secret}
	raw := []byte(secret)
	label := "[REDACTED:KEY]"

	variants := []struct {
		name    string
		encoded string
	}{
		{"literal", secret},
		{"base64-std", base64.StdEncoding.EncodeToString(raw)},
		{"base64-url", base64.URLEncoding.EncodeToString(raw)},
		{"base64-raw-std", base64.RawStdEncoding.EncodeToString(raw)},
		{"base64-raw-url", base64.RawURLEncoding.EncodeToString(raw)},
		{"url-escape", url.QueryEscape(secret)},
		{"hex-lower", hex.EncodeToString(raw)},
		{"hex-upper", strings.ToUpper(hex.EncodeToString(raw))},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			data := []byte("prefix " + v.encoded + " suffix")
			got := string(RedactBytes(data, secrets))
			want := "prefix " + label + " suffix"
			if got != want {
				t.Errorf("variant %s: got %q, want %q", v.name, got, want)
			}
		})
	}
}
