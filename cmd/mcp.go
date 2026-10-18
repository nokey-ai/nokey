package cmd

import (
	"fmt"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/approval"
	_ "github.com/nokey-ai/nokey/internal/integration/github"
	"github.com/nokey-ai/nokey/internal/mcpserver"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/version"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Model Context Protocol (MCP) server for AI tool integration",
	Long: `Run nokey as an MCP server so AI tools (Claude Code, Cursor, etc.)
can execute commands with secrets injected as environment variables.

Secrets never appear in tool output — all output is automatically redacted.
Each secret access is checked against policies.yaml, may ask the user to
approve it through an MCP elicitation prompt or require an access token
from mint_token, and is still subject to the OS keyring ACL (on macOS,
Keychain can prompt the user to approve a read).

Subcommands:
  serve  - Start the MCP stdio server`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP stdio server",
	Long: `Start a JSON-RPC stdio server implementing the Model Context Protocol.

AI tools connect by launching this process and communicating over stdin/stdout.

Add it to Claude Code:
  claude mcp add nokey -- nokey mcp serve

or share it with a project through .mcp.json:
  {
    "mcpServers": {
      "nokey": {
        "command": "nokey",
        "args": ["mcp", "serve"]
      }
    }
  }`,
	RunE: runMCPServe,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}
	polStore, err := policy.NewStore(configDir)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	h := mcpserver.New(mcpserver.Deps{
		GetStore:     func() (mcpserver.SecretStore, error) { return getKeyring() },
		GetPolicy:    polStore.Current,
		Config:       cfg,
		ApprovalFn:   approval.RequestWithDetail,
		AuditFn:      recordAudit,
		GetConfigDir: getConfigDir,
	})

	s := newMCPServer()
	h.RegisterTools(s)

	return server.ServeStdio(s)
}

// mcpInstructions is sent to clients at initialize, for the model to read
// before it picks a tool.
const mcpInstructions = `nokey runs commands with secrets from the OS keyring without revealing their values. All output is redacted: secret values appear as [REDACTED:NAME].

Call list_secrets first to see which secret names exist.

Prefer exec_with_secrets: put ${{NOKEY:NAME}} placeholders in args (for example a header value). Only the referenced secrets are read, and they never enter the environment. Use exec when a program reads its credentials from environment variables; narrow what it receives with only/except.

The user may be asked to approve access through an elicitation prompt. policies.yaml can deny a command or require a token: mint_token creates a short-lived lease (it needs approval once) that you pass as the token parameter. The github_* tools use the GITHUB_TOKEN secret and are checked by policy as the command nokey:integration:github.`

// newMCPServer builds the MCP server with nokey's options.
func newMCPServer() *server.MCPServer {
	return server.NewMCPServer("nokey", version.Version,
		server.WithToolCapabilities(false),
		server.WithElicitation(),
		server.WithInstructions(mcpInstructions),
		// A panic in one tool call must not take down the server.
		server.WithRecovery(),
	)
}
