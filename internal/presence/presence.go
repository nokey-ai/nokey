// Package presence asks the person at the machine to confirm an action in
// a way that a program running as the same user cannot answer for them.
//
// nokey's other prompts can be answered by such a program: an MCP client
// answers its own elicitation prompts, stdin can be piped, and a
// pseudo-terminal passes a TTY check. Presence uses the operating system's
// own authentication dialog (Touch ID or the login password on macOS),
// which only the person at the machine can complete.
package presence

import (
	"context"
	"errors"
	"unicode/utf8"
)

// ErrUnavailable means this machine has no presence check nokey can use:
// another platform, no GUI session, or no passcode set. Callers must treat
// it as a refusal unless they have another human-only factor, such as a
// fresh PIN entry.
var ErrUnavailable = errors.New("no Touch ID or login-password prompt is available")

// maxReasonBytes caps the reason shown in the dialog, which has little room.
const maxReasonBytes = 400

// Confirm shows reason in the system authentication dialog and returns nil
// only if the person at the machine authenticates. It returns an error
// wrapping ErrUnavailable when no dialog can be shown, and another error
// when the person cancels or fails.
func Confirm(ctx context.Context, reason string) error {
	return confirm(ctx, capReason(reason))
}

// capReason cuts reason to maxReasonBytes on a rune boundary.
func capReason(reason string) string {
	if len(reason) <= maxReasonBytes {
		return reason
	}
	cut := maxReasonBytes
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "…"
}
