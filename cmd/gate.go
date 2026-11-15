package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/mcpserver"
	"github.com/nokey-ai/nokey/internal/presence"
	"github.com/spf13/cobra"
)

// presenceConfirmFn shows the system authentication dialog. Wrapped so
// tests can stand in for the person at the machine.
var presenceConfirmFn = presence.Confirm

// cmdContext returns cmd's context, or context.Background() for a nil
// command or one run without a context.
func cmdContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

// confirmHuman asks the person at the machine to approve reason. It uses
// the presence dialog, and where there is none it asks for the PIN afresh
// (never from the session ticket). With neither it refuses: a y/N prompt
// on stdin is no gate, since any program can answer it.
//
// pinFollows says the caller asks for the PIN afresh itself straight
// after, so the fallback leaves that prompt to it instead of asking twice.
func confirmHuman(ctx context.Context, store *keyring.Store, reason string, pinFollows bool) error {
	err := presenceConfirmFn(ctx, reason)
	if err == nil || !errors.Is(err, presence.ErrUnavailable) {
		return err
	}
	if !store.HasPIN() {
		return fmt.Errorf("%s needs Touch ID, the login password or a PIN, and none is available (%w); run 'nokey auth setup' to set a PIN", reason, err)
	}
	if pinFollows {
		return nil
	}
	storedHash, hashErr := store.GetPINHash()
	if hashErr != nil {
		return hashErr
	}
	return authAuthenticateFn(storedHash)
}

// mcpApprovalFn and mcpRememberApprovalFn are the approval prompts
// `nokey mcp serve` uses: elicitation, then the presence dialog.
var (
	mcpApprovalFn         = presenceApproval(approval.RequestWithDetail)
	mcpRememberApprovalFn = presenceRememberApproval(approval.RequestRememberable)
)

// presenceApproval puts the presence dialog after an MCP elicitation
// prompt. The MCP client answers elicitation, and the client may be the
// very agent asking for the secret, so its Accept only lets the request
// reach the person at the machine. The MCP server has no terminal, so
// there is no PIN fallback: with no presence dialog, approval fails.
func presenceApproval(prompt mcpserver.ApprovalFunc) mcpserver.ApprovalFunc {
	return func(ctx context.Context, r approval.Requester, command string, secretNames []string, detail string) error {
		if err := prompt(ctx, r, command, secretNames, detail); err != nil {
			return err
		}
		return presenceConfirmFn(ctx, presenceReason(command, secretNames))
	}
}

// presenceRememberApproval is presenceApproval for prompts that offer
// "don't ask again this session". The choice is only returned once the
// presence dialog has passed, so a grant can't skip it.
func presenceRememberApproval(prompt mcpserver.RememberApprovalFunc) mcpserver.RememberApprovalFunc {
	return func(ctx context.Context, r approval.Requester, command string, secretNames []string, detail string) (bool, error) {
		remember, err := prompt(ctx, r, command, secretNames, detail)
		if err != nil {
			return false, err
		}
		if err := presenceConfirmFn(ctx, presenceReason(command, secretNames)); err != nil {
			return false, err
		}
		return remember, nil
	}
}

// presenceReason is the dialog text for command reading secretNames. macOS
// shows it as "nokey is trying to <reason>".
func presenceReason(command string, secretNames []string) string {
	return fmt.Sprintf("approve %s with secrets %s", approval.Quote(command), approval.Quote(strings.Join(secretNames, ", ")))
}
