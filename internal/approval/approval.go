package approval

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Requester abstracts MCP elicitation so callers can be tested with a mock.
type Requester interface {
	RequestElicitation(ctx context.Context, request mcp.ElicitationRequest) (*mcp.ElicitationResult, error)
}

// Request sends an MCP elicitation prompt asking the user to approve
// secret access for the given command. Returns nil if approved, an error otherwise.
// Fail-closed: if the client does not support elicitation, access is denied.
func Request(ctx context.Context, requester Requester, command string, secretNames []string) error {
	msg := fmt.Sprintf(
		"nokey: %q wants to access secret(s): %s\n\nDo you approve?",
		command, strings.Join(secretNames, ", "),
	)

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
