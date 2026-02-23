package placeholder

import (
	"reflect"
	"testing"
)

func TestContainsPlaceholder(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid placeholder",
			input: "${{NOKEY:MY_SECRET}}",
			want:  true,
		},
		{
			name:  "embedded in string",
			input: "Bearer ${{NOKEY:TOKEN}}",
			want:  true,
		},
		{
			name:  "hyphenated name",
			input: "${{NOKEY:my-api-key}}",
			want:  true,
		},
		{
			name:  "no placeholder",
			input: "just a plain string",
			want:  false,
		},
		{
			name:  "malformed missing closing braces",
			input: "${{NOKEY:SECRET",
			want:  false,
		},
		{
			name:  "malformed wrong prefix",
			input: "${{OTHER:SECRET}}",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsPlaceholder(tt.input); got != tt.want {
				t.Errorf("ContainsPlaceholder(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    []string
	}{
		{
			name:    "single placeholder in args",
			command: "curl",
			args:    []string{"-H", "Authorization: Bearer ${{NOKEY:TOKEN}}"},
			want:    []string{"TOKEN"},
		},
		{
			name:    "multiple across args",
			command: "curl",
			args:    []string{"-u", "${{NOKEY:USER}}:${{NOKEY:PASS}}", "${{NOKEY:URL}}"},
			want:    []string{"PASS", "URL", "USER"},
		},
		{
			name:    "deduplication",
			command: "",
			args:    []string{"${{NOKEY:KEY}}", "${{NOKEY:KEY}}"},
			want:    []string{"KEY"},
		},
		{
			name:    "no placeholders",
			command: "echo",
			args:    []string{"hello", "world"},
			want:    []string{},
		},
		{
			name:    "placeholder in command",
			command: "${{NOKEY:CMD}}",
			args:    nil,
			want:    []string{"CMD"},
		},
		{
			name:    "malformed patterns ignored",
			command: "",
			args:    []string{"${{NOKEY:}}", "${{OTHER:KEY}}", "${{NOKEY:VALID}}"},
			want:    []string{"VALID"},
		},
		{
			name:    "nil args",
			command: "",
			args:    nil,
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Extract(tt.command, tt.args)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Extract(%q, %v) = %v, want %v", tt.command, tt.args, got, tt.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		secrets map[string]string
		want    []string
		wantErr bool
	}{
		{
			name:    "single replacement",
			args:    []string{"${{NOKEY:TOKEN}}"},
			secrets: map[string]string{"TOKEN": "sk-abc123"},
			want:    []string{"sk-abc123"},
		},
		{
			name:    "embedded in string",
			args:    []string{"Bearer ${{NOKEY:TOKEN}}"},
			secrets: map[string]string{"TOKEN": "sk-abc123"},
			want:    []string{"Bearer sk-abc123"},
		},
		{
			name:    "multiple in one arg",
			args:    []string{"${{NOKEY:USER}}:${{NOKEY:PASS}}"},
			secrets: map[string]string{"USER": "admin", "PASS": "hunter2"},
			want:    []string{"admin:hunter2"},
		},
		{
			name:    "multiple args",
			args:    []string{"-H", "Authorization: ${{NOKEY:TOKEN}}", "--url", "${{NOKEY:URL}}"},
			secrets: map[string]string{"TOKEN": "Bearer xyz", "URL": "https://api.example.com"},
			want:    []string{"-H", "Authorization: Bearer xyz", "--url", "https://api.example.com"},
		},
		{
			name:    "no placeholders passes through",
			args:    []string{"hello", "world"},
			secrets: map[string]string{"UNUSED": "value"},
			want:    []string{"hello", "world"},
		},
		{
			name:    "missing secret errors",
			args:    []string{"${{NOKEY:MISSING}}"},
			secrets: map[string]string{},
			wantErr: true,
		},
		{
			name:    "nil args returns empty",
			args:    nil,
			secrets: map[string]string{},
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.args, tt.secrets)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Resolve() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Resolve() unexpected error: %v", err)
				return
			}
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Resolve() = %v, want %v", got, tt.want)
			}
		})
	}
}
