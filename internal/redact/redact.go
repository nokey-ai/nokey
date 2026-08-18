package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/nokey-ai/nokey/internal/sensitive"
)

// minSecretLenForVariants is the minimum secret length to generate encoding
// variants. Shorter secrets produce too many false positives.
const minSecretLenForVariants = 8

// redactor handles the actual redaction logic
type redactor struct {
	replacements map[string]string // value -> replacement
	sortedKeys   []string          // longest first for greedy matching
	maxLen       int               // length of the longest match target
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

	if len(r.sortedKeys) > 0 {
		r.maxLen = len(r.sortedKeys[0])
	}

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
	// Collect keys before clearing — ClearString mutates the backing bytes,
	// which corrupts map hashes and prevents subsequent deletes.
	keys := make([]string, 0, len(r.replacements))
	for k := range r.replacements {
		keys = append(keys, k)
	}
	for _, k := range keys {
		delete(r.replacements, k)
		sensitive.ClearString(k)
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

// pendingLen reports how many trailing bytes of data must be withheld because
// they could be the opening of a secret that the next read completes.
//
// It answers 0 whenever the tail cannot begin any match, which is the ordinary
// case for terminal output. That matters: this runs against a PTY, and
// withholding a fixed-size tail from every write would swallow the end of any
// prompt that does not finish with a newline until more output arrived.
func (r *redactor) pendingLen(data []byte) int {
	n := r.maxLen - 1
	if n > len(data) {
		n = len(data)
	}

	for ; n > 0; n-- {
		suffix := string(data[len(data)-n:])
		for _, key := range r.sortedKeys {
			// Only a proper prefix is interesting: an exact-length match would
			// already have been replaced by redact.
			if len(key) > n && strings.HasPrefix(key, suffix) {
				return n
			}
		}
	}

	return 0
}

// redactingReader wraps an io.Reader and redacts secrets from the data.
//
// Matching spans reads. A secret arriving in two pieces — the tail of one read
// and the head of the next — is still caught, because any tail that could
// begin a secret is held back until the following read confirms or refutes it.
type redactingReader struct {
	reader   io.Reader
	redactor *redactor
	out      []byte // redacted bytes ready for the caller
	hold     []byte // withheld tail; may be the start of a secret
	done     bool   // underlying reader is finished
	err      error  // its terminal error, returned once out and hold drain
}

func (r *redactingReader) Read(p []byte) (int, error) {
	for {
		// Serve whatever is already redacted.
		if len(r.out) > 0 {
			n := copy(p, r.out)
			r.out = r.out[n:]
			return n, nil
		}

		// Source finished: the held tail can no longer grow into a secret, so
		// redact what is there and release it before reporting the error.
		if r.done {
			if len(r.hold) > 0 {
				r.out = r.redactor.redact(r.hold)
				r.hold = nil
				continue
			}
			return 0, r.err
		}

		if len(p) == 0 {
			return 0, nil
		}

		readBuf := make([]byte, len(p))
		nRead, readErr := r.reader.Read(readBuf)
		if nRead > 0 {
			combined := append(r.hold, readBuf[:nRead]...)
			redacted := r.redactor.redact(combined)

			keep := r.redactor.pendingLen(redacted)
			split := len(redacted) - keep

			r.out = redacted[:split]
			// Copy the tail: redacted may alias combined, whose backing array
			// the next append would overwrite.
			r.hold = append([]byte(nil), redacted[split:]...)
		}

		if readErr != nil {
			r.done = true
			r.err = readErr
		}

		// Nothing to hand over yet — every byte read is still pending. Go back
		// for more rather than reporting a zero-length read.
		if len(r.out) == 0 && !r.done {
			continue
		}
	}
}

// Clear zeros the buffers holding in-flight output. The held tail is by
// construction a fragment of a secret, and out may carry secret bytes that
// were too short to match.
func (r *redactingReader) Clear() {
	sensitive.ClearBytes(r.out)
	sensitive.ClearBytes(r.hold)
	r.out = nil
	r.hold = nil
}
