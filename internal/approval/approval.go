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

// RequestWithDetail sends an MCP elicitation prompt asking the user to
// approve secret access for the given command. Returns nil if approved, an
// error otherwise. Fail-closed: if the client does not support elicitation,
// access is denied. detail is an extra line describing what is being
// approved — the arguments the command will run with, or the scope of a
// token — so the user isn't approving a bare command name; it may be empty.
//
// The client's Accept button is the approval and Decline or Cancel denies;
// the form asks no yes/no question of its own, so there is no second answer
// that could disagree with the button.
func RequestWithDetail(ctx context.Context, requester Requester, command string, secretNames []string, detail string) error {
	_, err := request(ctx, requester, command, secretNames, detail, false)
	return err
}

// RequestRememberable is RequestWithDetail with an optional "don't ask
// again this session" checkbox. remember is true only when the user
// accepted with the box ticked.
func RequestRememberable(ctx context.Context, requester Requester, command string, secretNames []string, detail string) (remember bool, err error) {
	return request(ctx, requester, command, secretNames, detail, true)
}

func request(ctx context.Context, requester Requester, command string, secretNames []string, detail string, offerRemember bool) (bool, error) {
	msg := fmt.Sprintf(
		"nokey: %q wants to access secret(s): %s\n\n",
		command, strings.Join(secretNames, ", "),
	)
	if detail != "" {
		msg += detail + "\n\n"
	}
	msg += "Accept to approve, Decline to deny."

	properties := map[string]any{}
	if offerRemember {
		properties["remember"] = map[string]any{
			"type":        "boolean",
			"title":       "Don't ask again this session",
			"description": fmt.Sprintf("Approve %s with these secrets (or fewer) without prompting until this MCP session ends", Quote(command)),
			"default":     false,
		}
	}

	result, err := requester.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: msg,
			RequestedSchema: map[string]any{
				"type":       "object",
				"properties": properties,
			},
		},
	})
	if err != nil {
		if errors.Is(err, server.ErrElicitationNotSupported) {
			return false, fmt.Errorf("approval required but client does not support elicitation prompts")
		}
		if errors.Is(err, server.ErrNoActiveSession) {
			return false, fmt.Errorf("approval required but no active MCP session")
		}
		return false, fmt.Errorf("approval request failed: %w", err)
	}

	switch result.Action {
	case mcp.ElicitationResponseActionAccept:
		return offerRemember && remembered(result.Content), nil
	case mcp.ElicitationResponseActionDecline:
		return false, fmt.Errorf("user declined secret access for %q", command)
	case mcp.ElicitationResponseActionCancel:
		return false, fmt.Errorf("user cancelled secret access for %q", command)
	default:
		return false, fmt.Errorf("unexpected elicitation response: %s", result.Action)
	}
}

// remembered reports whether elicitation content carries remember: true.
// The transport decodes content from JSON, so it is a map[string]any; a
// missing field or any value but boolean true means "ask again next time".
func remembered(content any) bool {
	c, ok := content.(map[string]any)
	if !ok {
		return false
	}
	remember, ok := c["remember"].(bool)
	return ok && remember
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
