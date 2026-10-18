package approval

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Requester abstracts MCP elicitation so callers can be tested with a mock.
type Requester interface {
	RequestElicitation(ctx context.Context, request mcp.ElicitationRequest) (*mcp.ElicitationResult, error)
}

// maxDetailArgsBytes caps how much of an argument list FormatArgs shows, so
// a huge argv can't push the rest of the prompt off screen.
const maxDetailArgsBytes = 512

// maxDetailValueBytes caps one model-supplied value shown by Quote.
const maxDetailValueBytes = 256

// stdinPreviewBytes is how much of stdin FormatStdin shows.
const stdinPreviewBytes = 64

// Request sends an MCP elicitation prompt asking the user to approve
// secret access for the given command. Returns nil if approved, an error otherwise.
// Fail-closed: if the client does not support elicitation, access is denied.
func Request(ctx context.Context, requester Requester, command string, secretNames []string) error {
	return RequestWithDetail(ctx, requester, command, secretNames, "")
}

// RequestWithDetail is Request with an extra line describing what is being
// approved — the arguments the command will run with, or the scope of a
// token — so the user isn't approving a bare command name. An empty detail
// gives exactly Request's prompt.
func RequestWithDetail(ctx context.Context, requester Requester, command string, secretNames []string, detail string) error {
	msg := fmt.Sprintf(
		"nokey: %q wants to access secret(s): %s\n\n",
		command, strings.Join(secretNames, ", "),
	)
	if detail != "" {
		msg += detail + "\n\n"
	}
	msg += "Do you approve?"

	result, err := requester.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: msg,
			RequestedSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"approve": map[string]any{
						"type":        "boolean",
						"description": "Approve secret access",
					},
				},
			},
		},
	})
	if err != nil {
		if errors.Is(err, server.ErrElicitationNotSupported) {
			return fmt.Errorf("approval required but client does not support elicitation prompts")
		}
		if errors.Is(err, server.ErrNoActiveSession) {
			return fmt.Errorf("approval required but no active MCP session")
		}
		return fmt.Errorf("approval request failed: %w", err)
	}

	switch result.Action {
	case mcp.ElicitationResponseActionAccept:
		return nil
	case mcp.ElicitationResponseActionDecline:
		return fmt.Errorf("user declined secret access for %q", command)
	case mcp.ElicitationResponseActionCancel:
		return fmt.Errorf("user cancelled secret access for %q", command)
	default:
		return fmt.Errorf("unexpected elicitation response: %s", result.Action)
	}
}

// Quote renders a model-supplied value for an approval prompt: %q-quoted,
// so a newline or control character can't forge a line of the prompt, and
// capped at maxDetailValueBytes.
func Quote(s string) string {
	return quoteCapped(s, maxDetailValueBytes)
}

func quoteCapped(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return fmt.Sprintf("%q", s)
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%q …(truncated)", s[:cut])
}

// FormatEnv renders extra environment variables for an approval prompt,
// sorted by name with each value quoted. Returns "" for none.
func FormatEnv(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.Sort(names)
	vars := make([]string, len(names))
	for i, name := range names {
		vars[i] = name + "=" + Quote(env[name])
	}
	line, hidden := capDetail("env: " + strings.Join(vars, " "))
	if hidden > 0 {
		line += fmt.Sprintf(" … (+%d more bytes; %d variables in all)", hidden, len(names))
	}
	return line
}

// FormatStdin describes stdin for an approval prompt: its size and a short
// quoted preview. Returns "" for none.
func FormatStdin(stdin string) string {
	if stdin == "" {
		return ""
	}
	return fmt.Sprintf("stdin: %d bytes, starting %s", len(stdin), quoteCapped(stdin, stdinPreviewBytes))
}

// FormatArgs renders args for an approval prompt: each one %q-quoted so
// control characters and spacing are visible, capped at maxDetailArgsBytes.
// Callers pass args before placeholders are resolved, so no secret value
// is shown. Returns "" for no args.
func FormatArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	line, hidden := capDetail("args: " + strings.Join(quoted, " "))
	if hidden > 0 {
		line += fmt.Sprintf(" … (+%d more bytes; %d args in all)", hidden, len(args))
	}
	return line
}

// capDetail cuts one line of detail to maxDetailArgsBytes, returning the
// kept part and how many bytes were cut. Callers say what was cut: what
// the prompt doesn't show still takes effect.
func capDetail(s string) (string, int) {
	if len(s) <= maxDetailArgsBytes {
		return s, 0
	}
	cut := maxDetailArgsBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], len(s) - cut
}
