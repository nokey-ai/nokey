package cmd

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/env"
	"github.com/nokey-ai/nokey/internal/redact"
	"github.com/nokey-ai/nokey/internal/version"
	"github.com/spf13/cobra"
)

const (
	maxOutputBytes     = 1 << 20 // 1 MiB
	defaultTimeoutSecs = 30
	maxTimeoutSecs     = 300
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
	s := server.NewMCPServer("nokey", version.Version,
		server.WithToolCapabilities(false),
	)

	readOnly := true

	// list_secrets — read-only, AI needs to know available secret names
	s.AddTool(
		mcp.NewTool("list_secrets",
			mcp.WithDescription("List all stored secret key names (not values)"),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{
				ReadOnlyHint: &readOnly,
			}),
		),
		handleListSecrets,
	)

	// exec — run a command with secrets injected, output always redacted
	s.AddTool(
		mcp.NewTool("exec",
			mcp.WithDescription("Execute a command with secrets injected as environment variables. Output is automatically redacted — secret values are replaced with [REDACTED:KEY_NAME]."),
			mcp.WithString("command",
				mcp.Required(),
				mcp.Description("Command to run"),
			),
			mcp.WithString("args",
				mcp.Description("Command arguments as a JSON array of strings"),
			),
			mcp.WithString("only",
				mcp.Description("Comma-separated secret names to inject (default: all)"),
			),
			mcp.WithString("except",
				mcp.Description("Comma-separated secret names to exclude"),
			),
			mcp.WithNumber("timeout_seconds",
				mcp.Description(fmt.Sprintf("Command timeout in seconds (default: %d, max: %d)", defaultTimeoutSecs, maxTimeoutSecs)),
			),
		),
		handleExec,
	)

	return server.ServeStdio(s)
}

func handleListSecrets(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	store, err := getKeyring()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	keys, err := store.List()
	if err != nil {
		recordAudit("mcp:list_secrets", "list_secrets", "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to list secrets: %s", err)), nil
	}

	recordAudit("mcp:list_secrets", "list_secrets", "all", true, "")

	if len(keys) == 0 {
		return mcp.NewToolResultText("No secrets stored."), nil
	}
	return mcp.NewToolResultText(strings.Join(keys, "\n")), nil
}

func handleExec(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Parse parameters
	command := request.GetString("command", "")
	if command == "" {
		return mcp.NewToolResultError("parameter 'command' is required"), nil
	}

	args := request.GetStringSlice("args", nil)
	only := request.GetString("only", "")
	except := request.GetString("except", "")

	timeoutSecs := request.GetInt("timeout_seconds", defaultTimeoutSecs)
	if timeoutSecs <= 0 {
		timeoutSecs = defaultTimeoutSecs
	}
	if timeoutSecs > maxTimeoutSecs {
		timeoutSecs = maxTimeoutSecs
	}

	// Get all secrets from keyring (no PIN auth — OS keyring ACL is the gate)
	store, err := getKeyring()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	allSecrets, err := store.GetAll()
	if err != nil {
		recordAudit("mcp:exec", command, "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to get secrets: %s", err)), nil
	}

	// Filter secrets based on only/except
	secrets, err := filterSecrets(allSecrets, only, except)
	if err != nil {
		recordAudit("mcp:exec", command, "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to filter secrets: %s", err)), nil
	}

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	cmd := osexec.CommandContext(ctx, command, args...)
	cmd.Env = env.MergeEnvironment(os.Environ(), secrets)
	cmd.Stdin = nil // non-interactive — stdin is the MCP JSON-RPC transport

	output, execErr := cmd.CombinedOutput()

	// Always redact output
	output = redact.RedactBytes(output, secrets)

	// Truncate if needed
	output = truncateOutput(output, maxOutputBytes)

	// Build result text
	exitCode := 0
	if execErr != nil {
		if exitError, ok := execErr.(*osexec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			recordAudit("mcp:exec", command, "all", false, "timeout")
			return mcp.NewToolResultError(fmt.Sprintf("command timed out after %d seconds", timeoutSecs)), nil
		} else {
			recordAudit("mcp:exec", command, "all", false, execErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to execute command: %s", execErr)), nil
		}
	}

	// Record audit
	secretNames := make([]string, 0, len(secrets))
	for name := range secrets {
		secretNames = append(secretNames, name)
	}
	errMsg := ""
	if execErr != nil {
		errMsg = execErr.Error()
	}
	recordAudit("mcp:exec", command, strings.Join(secretNames, ","), execErr == nil, errMsg)

	resultText := string(output)
	if exitCode != 0 {
		resultText = fmt.Sprintf("[exit code: %d]\n%s", exitCode, resultText)
	}

	return mcp.NewToolResultText(resultText), nil
}

// truncateOutput truncates output to maxBytes, appending a truncation notice.
func truncateOutput(data []byte, maxBytes int) []byte {
	if len(data) <= maxBytes {
		return data
	}
	notice := "\n\n[output truncated]"
	truncated := make([]byte, maxBytes)
	copy(truncated, data[:maxBytes-len(notice)])
	copy(truncated[maxBytes-len(notice):], notice)
	return truncated
}

// recordAudit logs an audit entry if auditing is enabled.
func recordAudit(operation, command, target string, success bool, errMsg string) {
	if cfg == nil || !cfg.Audit.Enabled {
		return
	}

	store, err := getKeyring()
	if err != nil {
		return
	}

	secretNames := []string{target}
	entry := audit.NewAuditEntry(operation, command, "keyring_acl", secretNames, success, errMsg)
	_ = audit.Record(store, entry)
}
