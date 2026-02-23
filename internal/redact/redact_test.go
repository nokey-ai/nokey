package redact

import (
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
