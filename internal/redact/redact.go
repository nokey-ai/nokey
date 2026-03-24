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
