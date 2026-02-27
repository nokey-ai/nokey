package redact

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
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
