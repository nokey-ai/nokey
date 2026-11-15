package presence

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCapReason(t *testing.T) {
	short := "nokey: gh wants GITHUB_TOKEN"
	if got := capReason(short); got != short {
		t.Errorf("capReason(short) = %q", got)
	}

	long := strings.Repeat("é", maxReasonBytes) // two bytes per rune
	got := capReason(long)
	if !utf8.ValidString(got) {
		t.Errorf("capReason cut a rune in half: %q", got)
	}
	if len(got) > maxReasonBytes+len("…") {
		t.Errorf("capReason left %d bytes, want at most %d", len(got), maxReasonBytes+len("…"))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("capReason should mark the cut: %q", got)
	}
}
