package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"time"
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
	if err != nil && !errors.Is(err, io.EOF) {
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
	if err != nil && !errors.Is(err, io.EOF) {
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
	if err != nil && !errors.Is(err, io.EOF) {
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
	if !errors.Is(err, io.EOF) {
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

// TestRedactBytes_BasicAuth is the curl -v -u user:${{NOKEY:PASS}} case. The
// password sits after "user:" inside the base64, at an offset that is not a
// multiple of three bytes, so none of its whole-value encodings appear.
func TestRedactBytes_BasicAuth(t *testing.T) {
	const secret = "hunter2-correct-horse"
	secrets := map[string]string{"PASS": secret}

	// One username per base64 offset of the password: 5, 6 and 7 bytes of
	// "user:" prefix leave it 2, 0 and 1 bytes into a group.
	for _, user := range []string{"user", "admin", "deploy"} {
		t.Run(user, func(t *testing.T) {
			creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + secret))
			line := "> Authorization: Basic " + creds + "\r\n"

			got := string(RedactBytes([]byte(line), secrets))
			before, after, ok := strings.Cut(got, "[REDACTED:PASS]")
			if !ok {
				t.Fatalf("password not redacted: %q", got)
			}
			// What survives either side of the label can only be the
			// username's encoding, one character that mixes it with the
			// password, and at the end a boundary character plus padding.
			before = strings.TrimPrefix(before, "> Authorization: Basic ")
			after = strings.TrimSuffix(after, "\r\n")
			if maxBefore := (len(user)+1)*8/6 + 1; len(before) > maxBefore {
				t.Errorf("%d characters before the label, want at most %d: %q", len(before), maxBefore, got)
			}
			if len(after) > 3 {
				t.Errorf("%d characters after the label, want at most 3: %q", len(after), got)
			}
		})
	}
}

func TestRedactBytes_PathAndJSONEscaped(t *testing.T) {
	const secret = "p@ss word/<&>\"quoted\"\\x"
	secrets := map[string]string{"PW": secret}
	label := "[REDACTED:PW]"

	jsonNoHTML := func(s string) string {
		var buf strings.Builder
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		out := strings.TrimSuffix(buf.String(), "\n")
		return out[1 : len(out)-1]
	}
	jsonHTML, _ := json.Marshal(secret)

	for _, v := range []struct {
		name    string
		encoded string
	}{
		{"path-escape", url.PathEscape(secret)},
		{"json", string(jsonHTML[1 : len(jsonHTML)-1])},
		{"json-no-html-escape", jsonNoHTML(secret)},
	} {
		t.Run(v.name, func(t *testing.T) {
			if v.encoded == secret {
				t.Fatalf("fixture does not exercise %s: encoding is the literal", v.name)
			}
			got := string(RedactBytes([]byte(`{"x":"`+v.encoded+`"}`), secrets))
			if want := `{"x":"` + label + `"}`; got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

// TestEncodingVariants_Base64MiddlesAreLongEnough guards against false
// positives: the offset base64 forms drop boundary characters, so for the
// shortest secret that gets variants they must still be long enough to be
// specific to it.
func TestEncodingVariants_Base64MiddlesAreLongEnough(t *testing.T) {
	for _, v := range encodingVariants(strings.Repeat("s", minSecretLenForVariants)) {
		if len(v) < minBase64MiddleLen {
			t.Errorf("variant %q is shorter than %d", v, minBase64MiddleLen)
		}
	}
}

// TestRedactBytes_LeavesUnrelatedBase64Alone checks that the offset forms do
// not eat base64 that merely shares a few characters with the secret's.
func TestRedactBytes_LeavesUnrelatedBase64Alone(t *testing.T) {
	secrets := map[string]string{"PASS": "hunter2-correct-horse"}
	for _, plain := range []string{"user:hunter2", "hunter3-correct-horse", "nothing secret in here at all"} {
		data := []byte(base64.StdEncoding.EncodeToString([]byte(plain)))
		if got := RedactBytes(data, secrets); !bytes.Equal(got, data) {
			t.Errorf("unrelated base64 of %q was changed: %q", plain, got)
		}
	}
}

// TestRedactBytes_DoesNotAliasInput protects callers that zero their buffer
// after redacting it: output with nothing to redact must still be a copy.
func TestRedactBytes_DoesNotAliasInput(t *testing.T) {
	data := []byte("nothing secret here")
	got := RedactBytes(data, map[string]string{"KEY": "sk-live-0123456789abcdef"})
	for i := range data {
		data[i] = 0
	}
	if string(got) != "nothing secret here" {
		t.Errorf("result changed when the input was zeroed: %q", got)
	}
}

// --- split-boundary redaction ---

// chunkReader hands out data in fixed-size pieces, the way a PTY delivers it.
type chunkReader struct {
	chunks [][]byte
	i      int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.i >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.i])
	if n < len(c.chunks[c.i]) {
		c.chunks[c.i] = c.chunks[c.i][n:]
		return n, nil
	}
	c.i++
	return n, nil
}

// TestRedactingReader_SecretSplitAcrossReads is the regression test for the
// split-boundary gap: redaction ran per chunk, so a secret delivered in two
// pieces matched neither and reached the terminal in the clear.
func TestRedactingReader_SecretSplitAcrossReads(t *testing.T) {
	const secret = "sk-live-0123456789abcdef"
	secrets := map[string]string{"API_KEY": secret}

	full := "prefix " + secret + " suffix"

	// Split at every offset, including inside the secret.
	for split := 1; split < len(full); split++ {
		t.Run(fmt.Sprintf("split_at_%d", split), func(t *testing.T) {
			reader := &redactingReader{
				reader: &chunkReader{chunks: [][]byte{
					[]byte(full[:split]),
					[]byte(full[split:]),
				}},
				redactor: newRedactor(secrets),
			}

			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}

			if strings.Contains(string(got), secret) {
				t.Errorf("secret leaked when split at %d: %q", split, got)
			}
			if !strings.Contains(string(got), "[REDACTED:API_KEY]") {
				t.Errorf("no redaction marker when split at %d: %q", split, got)
			}
			if want := "prefix [REDACTED:API_KEY] suffix"; string(got) != want {
				t.Errorf("output = %q, want %q", got, want)
			}
		})
	}
}

// TestRedactingReader_SecretSplitByteByByte is the pathological case: the
// secret arrives one byte per read.
func TestRedactingReader_SecretSplitByteByByte(t *testing.T) {
	const secret = "hunter2-hunter2-hunter2"
	full := "log: " + secret + "\n"

	chunks := make([][]byte, 0, len(full))
	for i := 0; i < len(full); i++ {
		chunks = append(chunks, []byte{full[i]})
	}

	reader := &redactingReader{
		reader:   &chunkReader{chunks: chunks},
		redactor: newRedactor(map[string]string{"PW": secret}),
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if strings.Contains(string(got), secret) {
		t.Errorf("secret leaked: %q", got)
	}
	if want := "log: [REDACTED:PW]\n"; string(got) != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

// TestRedactingReader_EncodedVariantSplitAcrossReads checks the holdback is
// sized from the longest encoded variant, not just the plaintext.
func TestRedactingReader_EncodedVariantSplitAcrossReads(t *testing.T) {
	const secret = "correct-horse-battery-staple"
	secrets := map[string]string{"TOKEN": secret}

	for _, tc := range []struct {
		name    string
		encoded string
	}{
		{"base64", base64.StdEncoding.EncodeToString([]byte(secret))},
		{"base64url", base64.URLEncoding.EncodeToString([]byte(secret))},
		{"hex", hex.EncodeToString([]byte(secret))},
		{"hex upper", strings.ToUpper(hex.EncodeToString([]byte(secret)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := "body=" + tc.encoded + "&x=1"
			for split := 1; split < len(full); split++ {
				reader := &redactingReader{
					reader: &chunkReader{chunks: [][]byte{
						[]byte(full[:split]),
						[]byte(full[split:]),
					}},
					redactor: newRedactor(secrets),
				}

				got, err := io.ReadAll(reader)
				if err != nil {
					t.Fatalf("ReadAll: %v", err)
				}
				if strings.Contains(string(got), tc.encoded) {
					t.Fatalf("encoded secret leaked when split at %d: %q", split, got)
				}
			}
		})
	}
}

// TestRedactingReader_DoesNotWithholdOrdinaryOutput guards the interactive
// case: a prompt with no trailing newline must reach the terminal immediately,
// not sit in the holdback waiting for output that only arrives after the user
// answers.
func TestRedactingReader_DoesNotWithholdOrdinaryOutput(t *testing.T) {
	secrets := map[string]string{"API_KEY": "sk-live-0123456789abcdef"}

	const prompt = "Continue? [y/N]: "
	reader := &redactingReader{
		reader:   &chunkReader{chunks: [][]byte{[]byte(prompt)}},
		redactor: newRedactor(secrets),
	}

	buf := make([]byte, 256)
	n, err := reader.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != prompt {
		t.Errorf("first Read returned %q, want the whole prompt %q", buf[:n], prompt)
	}
}

// TestRedactingReader_WithholdsOnlyPossiblePrefix checks the complement: a
// tail that really could open a secret is held until the next read settles it.
func TestRedactingReader_WithholdsOnlyPossiblePrefix(t *testing.T) {
	const secret = "sk-live-0123456789abcdef"
	r := newRedactor(map[string]string{"API_KEY": secret})

	if got := r.pendingLen([]byte("nothing to see here")); got != 0 {
		t.Errorf("pendingLen for ordinary text = %d, want 0", got)
	}
	if got := r.pendingLen([]byte("token: sk-live-01")); got != len("sk-live-01") {
		t.Errorf("pendingLen for a partial secret = %d, want %d", got, len("sk-live-01"))
	}
	if got := r.pendingLen([]byte("done " + secret)); got != 0 {
		t.Errorf("pendingLen after a complete secret = %d, want 0", got)
	}
}

func TestRedactingReader_Clear(t *testing.T) {
	reader := &redactingReader{
		reader:   &chunkReader{chunks: [][]byte{[]byte("partial sk-live-01")}},
		redactor: newRedactor(map[string]string{"API_KEY": "sk-live-0123456789abcdef"}),
	}

	buf := make([]byte, 8)
	_, _ = reader.Read(buf)

	reader.Clear()
	if reader.out != nil || reader.hold != nil {
		t.Error("Clear should release the in-flight buffers")
	}
}

// TestRedactingReader_PeriodicSecretBoundedHoldback is the pathological case
// for the straddling-match rule: in a long run of a periodic secret every
// position starts a complete match, so without a bound the split walked back
// to the start of the buffer, the holdback grew with the stream and nothing
// was released until EOF.
func TestRedactingReader_PeriodicSecretBoundedHoldback(t *testing.T) {
	secrets := map[string]string{"A": strings.Repeat("a", 12)}

	run := func(size int) time.Duration {
		data := bytes.Repeat([]byte("a"), size)
		var chunks [][]byte
		for rest := data; len(rest) > 0; {
			n := min(4096, len(rest))
			chunks = append(chunks, rest[:n])
			rest = rest[n:]
		}
		src := &chunkReader{chunks: chunks}
		reader := &redactingReader{reader: src, redactor: newRedactor(secrets)}
		limit := 2 * reader.redactor.maxLen

		start := time.Now()
		var got []byte
		buf := make([]byte, 4096)
		for {
			n, err := reader.Read(buf)
			if len(got) == 0 && src.i > 2 {
				t.Fatalf("first output only after %d of %d reads", src.i, len(chunks))
			}
			got = append(got, buf[:n]...)
			if len(reader.hold) > limit {
				t.Fatalf("holdback is %d bytes after %d bytes of output, want at most %d", len(reader.hold), len(got), limit)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
		}
		elapsed := time.Since(start)

		if want := RedactBytes(data, secrets); !bytes.Equal(got, want) {
			t.Fatalf("stream differs from RedactBytes for %d bytes (got %d bytes, want %d)", size, len(got), len(want))
		}
		return elapsed
	}

	small := run(128 << 10)
	large := run(1 << 20)
	// Eight times the input should cost about eight times as long; a
	// quadratic holdback makes it sixty-four.
	if small > 0 && large > 32*small {
		t.Errorf("1 MiB took %v, 128 KiB took %v: not linear", large, small)
	}
}

// --- benchmarks ---

// benchSecrets is a handful of realistic secrets, all long enough to get
// encoding variants.
var benchSecrets = map[string]string{
	"API_KEY":      "sk-live-0123456789abcdef0123456789abcdef",
	"DB_PASSWORD":  "correct-horse-battery-staple",
	"GITHUB_TOKEN": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
	"AWS_SECRET":   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

// benchOutput is 64 KiB of ordinary log text with no secrets in it, which is
// what the redactor sees almost all of the time.
var benchOutput = []byte(strings.Repeat("2026-10-17T12:00:00Z INFO request served path=/api/v1/items status=200 dur=12ms\n", 820))

func BenchmarkRedactBytes_NoMatch(b *testing.B) {
	r := newRedactor(benchSecrets)
	b.SetBytes(int64(len(benchOutput)))
	b.ReportAllocs()
	for b.Loop() {
		_ = r.redact(benchOutput)
	}
}

func BenchmarkRedactBytes_WithMatches(b *testing.B) {
	data := append([]byte(nil), benchOutput...)
	data = append(data, "token="+benchSecrets["API_KEY"]+"\n"...)
	data = append(data, "auth="+base64.StdEncoding.EncodeToString([]byte(benchSecrets["DB_PASSWORD"]))+"\n"...)
	r := newRedactor(benchSecrets)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		_ = r.redact(data)
	}
}

// BenchmarkRedactingReader streams the output through the reader in 4 KiB
// reads, the way io.Copy drives it from a PTY.
func BenchmarkRedactingReader(b *testing.B) {
	r := newRedactor(benchSecrets)
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(benchOutput)))
	b.ReportAllocs()
	for b.Loop() {
		reader := &redactingReader{reader: bytes.NewReader(benchOutput), redactor: r}
		for {
			if _, err := reader.Read(buf); err != nil {
				break
			}
		}
	}
}

// --- fuzzing ---

// FuzzRedactingReader_MatchesRedactBytes checks the streaming invariant: no
// matter where the reads split the output, the reader produces exactly what
// RedactBytes produces for the whole output at once.
//
// Secrets containing '[' or ']' are skipped. Such a secret can match across
// a [REDACTED:...] label inserted for another secret, which makes the result
// depend on how the output was split; real secrets that look like redaction
// labels are not worth the extra holdback it would take to cover them.
//
// So are runs in which the reader had to take a bounded cut (see safeSplit):
// a chain of overlapping matches longer than twice the longest pattern, which
// takes periodic secrets that overlap each other, such as "00" and "0" in a
// run of zeros. There the reader keeps its holdback bounded rather than wait
// for the run to end; the labels it picks can differ from RedactBytes, and
// fragments shorter than a secret can remain unredacted (see boundedSplit).
// TestRedactingReader_PeriodicSecretBoundedHoldback covers the single-secret
// case, where the output is still exactly equal.
func FuzzRedactingReader_MatchesRedactBytes(f *testing.F) {
	f.Add([]byte("prefix sk-live-0123456789abcdef suffix"), "sk-live-0123456789abcdef", "", int64(1))
	f.Add([]byte("xabcdy"), "abcd", "xab", int64(2))
	f.Add([]byte("Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("user:hunter2-hunter2"))), "hunter2-hunter2", "user", int64(3))
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte("correct-horse-battery-staple"))+"\n"), "correct-horse-battery-staple", "", int64(4))

	f.Fuzz(func(t *testing.T, data []byte, s1, s2 string, seed int64) {
		if strings.ContainsAny(s1+s2, "[]") {
			t.Skip()
		}
		secrets := map[string]string{"A": s1, "B": s2}

		rng := rand.New(rand.NewSource(seed))
		var chunks [][]byte
		for rest := data; len(rest) > 0; {
			n := 1 + rng.Intn(len(rest))
			chunks = append(chunks, rest[:n])
			rest = rest[n:]
		}

		reader := &redactingReader{
			reader:   &chunkReader{chunks: chunks},
			redactor: newRedactor(secrets),
		}
		got, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if reader.inexact {
			t.Skip("bounded cut taken")
		}

		want := RedactBytes(data, secrets)
		if !bytes.Equal(got, want) {
			t.Errorf("stream = %q, whole = %q (chunks %q)", got, want, chunks)
		}
	})
}
