package cmd

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/env"
	"github.com/nokey-ai/nokey/internal/integration"
	_ "github.com/nokey-ai/nokey/internal/integration/github"
	"github.com/nokey-ai/nokey/internal/placeholder"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/nokey-ai/nokey/internal/redact"
	"github.com/nokey-ai/nokey/internal/sensitive"
	"github.com/nokey-ai/nokey/internal/token"
	"github.com/nokey-ai/nokey/internal/version"
	"github.com/spf13/cobra"
)

const (
	maxOutputBytes     = 1 << 20 // 1 MiB
	defaultTimeoutSecs = 30
	maxTimeoutSecs     = 300
	autoMintTTLSecs    = 3600 // 1 hour — session token lifetime
)

var pol *policy.Policy
var mcpSrv *server.MCPServer
var proxyServer *proxy.Server
var tokenStore *token.Store
var sessionTokenID string

// approvalRequestFn is injectable for testing.
var approvalRequestFn = approval.Request

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
		return err
	}
	pol, err = policy.Load(configDir)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	tokenStore = token.NewStore()
	sessionTokenID = ""

	s := server.NewMCPServer("nokey", version.Version,
		server.WithToolCapabilities(false),
		server.WithElicitation(),
	)
	mcpSrv = s

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
			mcp.WithString("token",
				mcp.Description("Access lease token ID. If valid, skips the approval prompt."),
			),
		),
		handleExec,
	)

	// exec_with_secrets — placeholder-based secret injection, output always redacted
	s.AddTool(
		mcp.NewTool("exec_with_secrets",
			mcp.WithDescription(
				"Execute a command with secret values resolved from placeholders. "+
					"Use ${{NOKEY:SECRET_NAME}} in args to reference secrets by name. "+
					"Only referenced secrets are fetched. Secrets are never placed in "+
					"environment variables. Output is automatically redacted.",
			),
			mcp.WithString("command",
				mcp.Required(),
				mcp.Description("Command to run (must not contain placeholders)"),
			),
			mcp.WithArray("args",
				mcp.WithStringItems(),
				mcp.Description(
					"Command arguments. Use ${{NOKEY:SECRET_NAME}} to inject a secret "+
						"value at that position.",
				),
			),
			mcp.WithNumber("timeout_seconds",
				mcp.Description(fmt.Sprintf("Command timeout in seconds (default: %d, max: %d)", defaultTimeoutSecs, maxTimeoutSecs)),
			),
			mcp.WithString("token",
				mcp.Description("Access lease token ID. If valid, skips the approval prompt."),
			),
		),
		handleExecWithSecrets,
	)

	// mint_token — create an access lease
	s.AddTool(
		mcp.NewTool("mint_token",
			mcp.WithDescription(
				"Mint a short-lived access lease token for one or more secrets. "+
					"The token can be passed to exec or exec_with_secrets to skip per-call approval. "+
					"Always requires user approval at mint time. Max TTL: 3600 seconds.",
			),
			mcp.WithArray("secrets",
				mcp.Required(),
				mcp.WithStringItems(),
				mcp.Description("Secret names this token authorizes"),
			),
			mcp.WithNumber("ttl_seconds",
				mcp.Required(),
				mcp.Description("Token lifetime in seconds (max 3600)"),
			),
			mcp.WithNumber("max_uses",
				mcp.Description("Maximum number of uses (0 or omit for unlimited, TTL-only)"),
			),
			mcp.WithString("for",
				mcp.Description("Command pattern this token is for (default: * for any)"),
			),
		),
		handleMintToken,
	)

	// revoke_token — revoke an access lease
	s.AddTool(
		mcp.NewTool("revoke_token",
			mcp.WithDescription("Revoke an access lease token by ID."),
			mcp.WithString("token_id",
				mcp.Required(),
				mcp.Description("The token ID to revoke"),
			),
		),
		handleRevokeToken,
	)

	// list_tokens — list active access leases
	s.AddTool(
		mcp.NewTool("list_tokens",
			mcp.WithDescription("List all active access lease tokens."),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{
				ReadOnlyHint: &readOnly,
			}),
		),
		handleListTokens,
	)

	// start_proxy — start the local HTTP/HTTPS proxy
	s.AddTool(
		mcp.NewTool("start_proxy",
			mcp.WithDescription(
				"Start a local HTTP/HTTPS proxy that injects secrets into request headers "+
					"based on proxy rules in policies.yaml. Returns the proxy address. "+
					"Set http_proxy and https_proxy to route requests through it.",
			),
			mcp.WithString("addr",
				mcp.Description("Address to listen on (default: 127.0.0.1:0 for random port)"),
			),
		),
		handleStartProxy,
	)

	// stop_proxy — stop the running proxy
	s.AddTool(
		mcp.NewTool("stop_proxy",
			mcp.WithDescription("Stop the running local HTTP/HTTPS proxy."),
		),
		handleStopProxy,
	)

	// Register pre-built integrations (GitHub, etc.)
	deps := integration.Deps{
		GetSecret: func(name string) (string, error) {
			store, err := getKeyring()
			if err != nil {
				return "", err
			}
			return store.Get(name)
		},
		Policy:    pol,
		Requester: s,
		AuditFn:   recordAudit,
		UseToken: func(id string, secrets []string) error {
			result := tokenStore.Use(id, secrets)
			if !result.Valid {
				return fmt.Errorf("token invalid: %s", result.Reason)
			}
			return nil
		},
	}
	for _, integ := range integration.All() {
		s.AddTools(integ.Tools(deps)...)
	}

	return server.ServeStdio(s)
}

func handleStartProxy(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// If already running, return the address.
	if proxyServer != nil {
		addr := proxyServer.Addr()
		if addr != "" {
			return mcp.NewToolResultText(fmt.Sprintf("Proxy already running on %s", addr)), nil
		}
	}

	configDir, err := getConfigDir()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get config directory: %s", err)), nil
	}

	// Load proxy rules from the already-loaded policy.
	rules := pol.ProxyRules()
	if len(rules) == 0 {
		return mcp.NewToolResultError("no proxy rules found in policies.yaml — add a proxy: section with rules"), nil
	}

	// Load or create CA.
	ca, err := proxy.LoadOrCreateCA(configDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to load/create CA: %s", err)), nil
	}

	// Fetch referenced secrets.
	secretNames := proxy.CollectSecretNames(rules)
	store, err := getKeyring()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	secrets := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		val, err := store.Get(name)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get secret %q: %s", name, err)), nil
		}
		secrets[name] = val
	}

	addr := request.GetString("addr", "127.0.0.1:0")

	srv := proxy.NewServer(ca, rules, secrets, pol, recordAudit)
	secrets = nil // Server owns the map now; Stop() handles cleanup.

	actualAddr, err := srv.Start(addr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to start proxy: %s", err)), nil
	}

	proxyServer = srv
	recordAudit("mcp:start_proxy", "proxy", strings.Join(secretNames, ","), true, "")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Proxy started on %s\n\nSet environment variables:\n  export http_proxy=http://%s\n  export https_proxy=http://%s\n\nCA cert: %s",
		actualAddr, actualAddr, actualAddr, filepath.Join(configDir, "ca", "ca-cert.pem"),
	)), nil
}

func handleStopProxy(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if proxyServer == nil {
		return mcp.NewToolResultText("No proxy running."), nil
	}

	if err := proxyServer.Stop(context.Background()); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to stop proxy: %s", err)), nil
	}

	proxyServer = nil
	recordAudit("mcp:stop_proxy", "proxy", "", true, "")
	return mcp.NewToolResultText("Proxy stopped."), nil
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

func handleExec(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	defer sensitive.ClearMap(allSecrets)

	// Filter secrets based on only/except
	secrets, err := filterSecrets(allSecrets, only, except)
	if err != nil {
		recordAudit("mcp:exec", command, "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to filter secrets: %s", err)), nil
	}

	// Enforce scoped policy
	secretNames := make([]string, 0, len(secrets))
	for name := range secrets {
		secretNames = append(secretNames, name)
	}
	if err := pol.Check(command, secretNames); err != nil {
		recordAudit("mcp:exec", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Token or approval gateway
	tokenID := request.GetString("token", "")
	if err := checkTokenOrApproval(ctx, tokenID, command, secretNames); err != nil {
		recordAudit("mcp:exec:approval", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Execute command with timeout
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	cmd := osexec.CommandContext(execCtx, command, args...)
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
		} else if execCtx.Err() == context.DeadlineExceeded {
			recordAudit("mcp:exec", command, "all", false, "timeout")
			return mcp.NewToolResultError(fmt.Sprintf("command timed out after %d seconds", timeoutSecs)), nil
		} else {
			recordAudit("mcp:exec", command, "all", false, execErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to execute command: %s", execErr)), nil
		}
	}

	// Record audit
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

func handleExecWithSecrets(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command := request.GetString("command", "")
	if command == "" {
		return mcp.NewToolResultError("parameter 'command' is required"), nil
	}

	// Reject placeholders in command — secret values must not control which binary runs
	if placeholder.ContainsPlaceholder(command) {
		return mcp.NewToolResultError("placeholders are not allowed in 'command' — use them only in 'args'"), nil
	}

	args := request.GetStringSlice("args", nil)

	timeoutSecs := request.GetInt("timeout_seconds", defaultTimeoutSecs)
	if timeoutSecs <= 0 {
		timeoutSecs = defaultTimeoutSecs
	}
	if timeoutSecs > maxTimeoutSecs {
		timeoutSecs = maxTimeoutSecs
	}

	// Extract referenced secret names from args
	secretNames := placeholder.Extract("", args)

	// Enforce scoped policy before touching the keyring
	if err := pol.Check(command, secretNames); err != nil {
		recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Token or approval gateway
	tokenID := request.GetString("token", "")
	if err := checkTokenOrApproval(ctx, tokenID, command, secretNames); err != nil {
		recordAudit("mcp:exec_with_secrets:approval", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	store, err := getKeyring()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	// Fetch only the secrets that are actually referenced
	secrets := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		val, err := store.Get(name)
		if err != nil {
			recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to get secret %q: %s", name, err)), nil
		}
		secrets[name] = val
	}
	defer sensitive.ClearMap(secrets)

	// Resolve placeholders in args
	resolvedArgs, err := placeholder.Resolve(args, secrets)
	if err != nil {
		recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to resolve placeholders: %s", err)), nil
	}

	// Execute with clean environment (no secrets in env vars)
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	cmd := osexec.CommandContext(execCtx, command, resolvedArgs...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil

	output, execErr := cmd.CombinedOutput()

	// Always redact output
	output = redact.RedactBytes(output, secrets)
	output = truncateOutput(output, maxOutputBytes)

	exitCode := 0
	if execErr != nil {
		if exitError, ok := execErr.(*osexec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, "timeout")
			return mcp.NewToolResultError(fmt.Sprintf("command timed out after %d seconds", timeoutSecs)), nil
		} else {
			recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, execErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to execute command: %s", execErr)), nil
		}
	}

	errMsg := ""
	if execErr != nil {
		errMsg = execErr.Error()
	}
	recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), execErr == nil, errMsg)

	resultText := string(output)
	if exitCode != 0 {
		resultText = fmt.Sprintf("[exit code: %d]\n%s", exitCode, resultText)
	}

	return mcp.NewToolResultText(resultText), nil
}

func handleMintToken(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	secrets := request.GetStringSlice("secrets", nil)
	if len(secrets) == 0 {
		return mcp.NewToolResultError("parameter 'secrets' is required and must be non-empty"), nil
	}

	ttlSecs := request.GetInt("ttl_seconds", 0)
	maxUses := request.GetInt("max_uses", 0)
	mintedFor := request.GetString("for", "*")

	// Minting always requires approval — this is the one-time consent gate.
	if err := approvalRequestFn(ctx, mcpSrv, "mint_token", secrets); err != nil {
		recordAudit("mcp:mint_token:approval", "mint_token", strings.Join(secrets, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}
	recordAudit("mcp:mint_token:approval", "mint_token", strings.Join(secrets, ","), true, "")

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets:   secrets,
		TTLSecs:   ttlSecs,
		MaxUses:   maxUses,
		MintedFor: mintedFor,
	})
	if err != nil {
		recordAudit("mcp:mint_token", "mint_token", strings.Join(secrets, ","), false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to mint token: %s", err)), nil
	}

	recordAudit("mcp:mint_token", "mint_token", strings.Join(secrets, ","), true, "")

	usesStr := "unlimited"
	if tok.MaxUses > 0 {
		usesStr = fmt.Sprintf("%d", tok.MaxUses)
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"Token minted.\n  ID: %s\n  Secrets: %s\n  TTL: %ds (expires %s)\n  Max uses: %s\n  For: %s",
		tok.ID,
		strings.Join(tok.Secrets, ", "),
		ttlSecs,
		tok.ExpiresAt.Format(time.RFC3339),
		usesStr,
		tok.MintedFor,
	)), nil
}

func handleRevokeToken(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokenID := request.GetString("token_id", "")
	if tokenID == "" {
		return mcp.NewToolResultError("parameter 'token_id' is required"), nil
	}

	if tokenStore.Revoke(tokenID) {
		recordAudit("mcp:revoke_token", "revoke_token", tokenID, true, "")
		return mcp.NewToolResultText("Token revoked."), nil
	}

	recordAudit("mcp:revoke_token", "revoke_token", tokenID, false, "not found")
	return mcp.NewToolResultError("token not found"), nil
}

func handleListTokens(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokens := tokenStore.List()

	if len(tokens) == 0 {
		return mcp.NewToolResultText("No active tokens."), nil
	}

	var sb strings.Builder
	for i, tok := range tokens {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		usesStr := "unlimited"
		if tok.MaxUses > 0 {
			usesStr = fmt.Sprintf("%d/%d", tok.UsesLeft, tok.MaxUses)
		}
		fmt.Fprintf(&sb, "ID: %s\nSecrets: %s\nUses: %s\nExpires: %s\nFor: %s",
			tok.ID,
			strings.Join(tok.Secrets, ", "),
			usesStr,
			tok.ExpiresAt.Format(time.RFC3339),
			tok.MintedFor,
		)
	}

	return mcp.NewToolResultText(sb.String()), nil
}

// checkTokenOrApproval validates a token if provided, enforces token_required policy,
// or falls through to the existing approval gateway.
func checkTokenOrApproval(ctx context.Context, tokenID, command string, secretNames []string) error {
	if tokenID != "" {
		result := tokenStore.Use(tokenID, secretNames)
		if result.Valid {
			recordAudit("mcp:token_use", command, strings.Join(secretNames, ","), true, "")
			return nil
		}
		return fmt.Errorf("token invalid: %s", result.Reason)
	}

	// Try cached session token (auto-minted).
	if sessionTokenID != "" {
		result := tokenStore.Validate(sessionTokenID, secretNames)
		if result.Valid {
			recordAudit("mcp:token_use", command, strings.Join(secretNames, ","), true, "")
			return nil
		}
		// Token expired or doesn't cover these secrets — clear and fall through.
		sessionTokenID = ""
	}

	// No token provided — check if policy requires one.
	if pol.RequiresToken(command, secretNames) {
		return fmt.Errorf("token required by policy — use mint_token to create an access lease")
	}

	// Auto-mint: one approval covers the rest of the session.
	if cfg != nil && cfg.Auth.AutoMintToken {
		if err := tryAutoMint(ctx, secretNames); err == nil {
			return nil
		}
		// Auto-mint declined or failed — fall through to per-call approval.
	}

	// Fall through to existing approval gateway.
	if pol.RequiresApproval(command, secretNames) {
		if err := approvalRequestFn(ctx, mcpSrv, command, secretNames); err != nil {
			return err
		}
	}

	return nil
}

// tryAutoMint requests a one-time approval to mint a session token covering all secrets.
func tryAutoMint(ctx context.Context, secretNames []string) error {
	// Gather all secret names so the token covers everything.
	store, err := getKeyring()
	if err != nil {
		return err
	}
	allNames, err := store.List()
	if err != nil {
		return err
	}
	if len(allNames) == 0 {
		allNames = secretNames
	}

	if err := approvalRequestFn(ctx, mcpSrv, "session_token", allNames); err != nil {
		return err
	}

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets:   allNames,
		TTLSecs:   autoMintTTLSecs,
		MaxUses:   0, // unlimited
		MintedFor: "*",
	})
	if err != nil {
		return err
	}

	sessionTokenID = tok.ID
	recordAudit("mcp:auto_mint", "session_token", strings.Join(allNames, ","), true, "")
	return nil
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
