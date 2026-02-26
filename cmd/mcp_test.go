package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestTruncateOutput(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		max      int
		wantLen  int
		wantTail string // expected suffix after truncation
	}{
		{
			name:    "under limit unchanged",
			data:    []byte("hello"),
			max:     100,
			wantLen: 5,
		},
		{
			name:    "exactly at limit unchanged",
			data:    []byte("hello"),
			max:     5,
			wantLen: 5,
		},
		{
			name:     "over limit truncated",
			data:     bytes.Repeat([]byte("x"), 200),
			max:      100,
			wantLen:  100,
			wantTail: "\n\n[output truncated]",
		},
		{
			name:    "nil data",
			data:    nil,
			max:     100,
			wantLen: 0,
		},
		{
			name:    "empty data",
			data:    []byte{},
			max:     100,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateOutput(tt.data, tt.max)
			if len(got) != tt.wantLen {
				t.Errorf("truncateOutput() len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantTail != "" && !strings.HasSuffix(string(got), tt.wantTail) {
				t.Errorf("truncateOutput() should end with %q, got tail %q",
					tt.wantTail, string(got[len(got)-len(tt.wantTail):]))
			}
		})
	}
}
