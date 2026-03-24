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
Each secret access is gated by the OS keyring ACL — on macOS, Keychain
prompts the user to approve every read.

Subcommands:
  serve  - Start the MCP stdio server`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP stdio server",
	Long: `Start a JSON-RPC stdio server implementing the Model Context Protocol.

AI tools connect by launching this process and communicating over stdin/stdout.

Example Claude Code configuration (~/.claude/claude_code_config.json):
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
	pol, err := policy.Load(configDir)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	h := mcpserver.New(mcpserver.Deps{
		GetStore:     func() (mcpserver.SecretStore, error) { return getKeyring() },
		Policy:       pol,
		Config:       cfg,
		ApprovalFn:   approval.Request,
		AuditFn:      recordAudit,
		GetConfigDir: getConfigDir,
	})

	s := server.NewMCPServer("nokey", version.Version,
		server.WithToolCapabilities(false),
		server.WithElicitation(),
	)
	h.RegisterTools(s)

	return server.ServeStdio(s)
}
