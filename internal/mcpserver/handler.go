package mcpserver

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/env"
	"github.com/nokey-ai/nokey/internal/integration"
	nokeyKeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/placeholder"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/nokey-ai/nokey/internal/redact"
	"github.com/nokey-ai/nokey/internal/sensitive"
	"github.com/nokey-ai/nokey/internal/token"
)

const (
	MaxOutputBytes     = 1 << 20 // 1 MiB
	DefaultTimeoutSecs = 30
	MaxTimeoutSecs     = 300
	AutoMintTTLSecs    = 3600 // 1 hour — session token lifetime
)

// autoMintPromptTimeout bounds how long an auto-mint approval prompt may
// stay unanswered. Calls arriving meanwhile wait for its outcome, so an
// abandoned prompt must end eventually; three minutes leaves time to read
// the prompt and switch windows. A var so tests can shorten it.
var autoMintPromptTimeout = 3 * time.Minute

// SecretStore is the subset of keyring functionality that MCP handlers need.
type SecretStore interface {
	Get(name string) (string, error)
	GetAll() (map[string]string, error)
	List() ([]string, error)
}

// ApprovalFunc is the signature for requesting user approval. detail says
// what exactly is being approved (see approval.RequestWithDetail).
type ApprovalFunc func(ctx context.Context, requester approval.Requester, command string, secretNames []string, detail string) error

// AuditFunc is the signature for recording audit entries.
// Matches the pattern used by proxy.AuditFunc and integration.Deps.AuditFn.
type AuditFunc func(operation, command, target string, success bool, errMsg string)

// Deps holds the injected dependencies for a Handler.
type Deps struct {
	GetStore func() (SecretStore, error)
	// GetPolicy returns the current policy, reloading from disk when the
	// source file has changed. Called per-request; must be safe for
	// concurrent use. A nil return value means allow-all.
	GetPolicy    func() *policy.Policy
	Config       *config.Config
	ApprovalFn   ApprovalFunc
	AuditFn      AuditFunc
	GetConfigDir func() (string, error)
}

// Handler holds session-scoped state and serves MCP tool requests.
type Handler struct {
	getStore     func() (SecretStore, error)
	getPolicy    func() *policy.Policy
	cfg          *config.Config
	approvalFn   ApprovalFunc
	auditFn      AuditFunc
	getConfigDir func() (string, error)

	tokenStore *token.Store
	mcpSrv     *server.MCPServer

	// mcp-go dispatches tool calls on a pool of workers, so handlers run
	// concurrently. proxyMu is held for the whole of start_proxy/stop_proxy
	// so two starts can't both pass the "already running" check.
	proxyMu     sync.Mutex
	proxyServer *proxy.Server

	// sessionMu guards sessionTokenID and minting. It is only ever held
	// briefly, never across a prompt, so reading the cached token can't
	// block behind a pending approval.
	sessionMu      sync.Mutex
	sessionTokenID string
	// minting is the auto-mint in flight, if any. Concurrent calls wait on
	// it and share its outcome instead of each raising a prompt.
	minting *mintCall
}

// mintCall is one in-flight auto-mint. done is closed once err is set.
type mintCall struct {
	done chan struct{}
	err  error
}

// New creates a Handler from the given dependencies.
func New(deps Deps) *Handler {
	auditFn := deps.AuditFn
	if auditFn == nil {
		auditFn = func(string, string, string, bool, string) {}
	}
	return &Handler{
		getStore:     deps.GetStore,
		getPolicy:    deps.GetPolicy,
		cfg:          deps.Config,
		approvalFn:   deps.ApprovalFn,
		auditFn:      auditFn,
		getConfigDir: deps.GetConfigDir,
		tokenStore:   token.NewStore(),
	}
}

// RegisterTools adds all MCP tool handlers to the server.
func (h *Handler) RegisterTools(s *server.MCPServer) {
	h.mcpSrv = s
	readOnly := true

	// list_secrets — read-only, AI needs to know available secret names
	s.AddTool(
		mcp.NewTool("list_secrets",
			mcp.WithDescription("List all stored secret key names (not values)"),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{
				ReadOnlyHint: &readOnly,
			}),
		),
		h.HandleListSecrets,
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
				mcp.Description(fmt.Sprintf("Command timeout in seconds (default: %d, max: %d)", DefaultTimeoutSecs, MaxTimeoutSecs)),
			),
			mcp.WithString("token",
				mcp.Description("Access lease token ID. If valid, skips the approval prompt."),
			),
		),
		h.HandleExec,
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
				mcp.Description(fmt.Sprintf("Command timeout in seconds (default: %d, max: %d)", DefaultTimeoutSecs, MaxTimeoutSecs)),
			),
			mcp.WithString("token",
				mcp.Description("Access lease token ID. If valid, skips the approval prompt."),
			),
		),
		h.HandleExecWithSecrets,
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
		h.HandleMintToken,
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
		h.HandleRevokeToken,
	)

	// list_tokens — list active access leases
	s.AddTool(
		mcp.NewTool("list_tokens",
			mcp.WithDescription("List all active access lease tokens."),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{
				ReadOnlyHint: &readOnly,
			}),
		),
		h.HandleListTokens,
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
				mcp.Description("Loopback address to listen on (default: 127.0.0.1:0 for random port). "+
					"Non-loopback addresses are rejected."),
			),
		),
		h.HandleStartProxy,
	)

	// stop_proxy — stop the running proxy
	s.AddTool(
		mcp.NewTool("stop_proxy",
			mcp.WithDescription("Stop the running local HTTP/HTTPS proxy."),
		),
		h.HandleStopProxy,
	)

	// Register pre-built integrations (GitHub, etc.)
	deps := integration.Deps{
		GetSecret: func(name string) (string, error) {
			store, err := h.getStore()
			if err != nil {
				return "", err
			}
			return store.Get(name)
		},
		GetPolicy: h.getPolicy,
		Requester: s,
		AuditFn:   h.recordAudit,
		UseToken: func(id, command string, secrets []string) error {
			result := h.tokenStore.UseFor(id, command, secrets)
			if !result.Valid {
				return tokenInvalid(result, command)
			}
			return nil
		},
	}
	for _, integ := range integration.All() {
		s.AddTools(integ.Tools(deps)...)
	}
}

func (h *Handler) HandleStartProxy(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h.proxyMu.Lock()
	defer h.proxyMu.Unlock()

	// If already running, return the address.
	if h.proxyServer != nil {
		addr := h.proxyServer.Addr()
		if addr != "" {
			return mcp.NewToolResultText(fmt.Sprintf("Proxy already running on %s", addr)), nil
		}
	}

	// Validate the caller-supplied address first. This comes from the model,
	// so refusing it before the keyring is opened means a bad address costs no
	// keychain unlock and loads no secrets into memory.
	addr := request.GetString("addr", "127.0.0.1:0")
	if err := proxy.ValidateListenAddr(addr); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	configDir, err := h.getConfigDir()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get config directory: %s", err)), nil
	}

	// Load proxy rules from the current policy (reloaded from disk if the
	// source file has changed since the last call).
	pol := h.getPolicy()
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
	store, err := h.getStore()
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

	srv := proxy.NewServer(ca, rules, secrets, pol, h.recordAudit)

	actualAddr, err := srv.Start(addr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to start proxy: %s", err)), nil
	}

	h.proxyServer = srv
	h.recordAudit("mcp:start_proxy", "proxy", strings.Join(secretNames, ","), true, "")

	return mcp.NewToolResultText(fmt.Sprintf(
		"Proxy started on %s\n\nSet environment variables:\n  export http_proxy=http://%s\n  export https_proxy=http://%s\n\nCA cert: %s",
		actualAddr, actualAddr, actualAddr, filepath.Join(configDir, "ca", "ca-cert.pem"),
	)), nil
}

func (h *Handler) HandleStopProxy(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h.proxyMu.Lock()
	defer h.proxyMu.Unlock()

	if h.proxyServer == nil {
		return mcp.NewToolResultText("No proxy running."), nil
	}

	if err := h.proxyServer.Stop(context.Background()); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to stop proxy: %s", err)), nil
	}

	h.proxyServer = nil
	h.recordAudit("mcp:stop_proxy", "proxy", "", true, "")
	return mcp.NewToolResultText("Proxy stopped."), nil
}

func (h *Handler) HandleListSecrets(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	store, err := h.getStore()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	keys, err := store.List()
	if err != nil {
		h.recordAudit("mcp:list_secrets", "list_secrets", "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to list secrets: %s", err)), nil
	}

	h.recordAudit("mcp:list_secrets", "list_secrets", "all", true, "")

	if len(keys) == 0 {
		return mcp.NewToolResultText("No secrets stored."), nil
	}
	return mcp.NewToolResultText(strings.Join(keys, "\n")), nil
}

func (h *Handler) HandleExec(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Parse parameters
	command := strings.TrimSpace(request.GetString("command", ""))
	if command == "" {
		return mcp.NewToolResultError("parameter 'command' is required"), nil
	}
	if strings.Contains(command, "..") {
		return mcp.NewToolResultError("command must not contain '..' (path traversal)"), nil
	}

	args := request.GetStringSlice("args", nil)
	only := request.GetString("only", "")
	except := request.GetString("except", "")

	// Validate only/except filter names
	if err := validateFilterNames(only, except); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	timeoutSecs := request.GetInt("timeout_seconds", DefaultTimeoutSecs)
	if timeoutSecs <= 0 {
		timeoutSecs = DefaultTimeoutSecs
	}
	if timeoutSecs > MaxTimeoutSecs {
		timeoutSecs = MaxTimeoutSecs
	}

	// Open keyring (no PIN auth — OS keyring ACL is the gate). Enumerate names
	// first so we can apply policy/approval *before* reading any secret values.
	store, err := h.getStore()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	allNames, err := store.List()
	if err != nil {
		h.recordAudit("mcp:exec", command, "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to list secrets: %s", err)), nil
	}

	// Filter names by only/except before touching the keyring for values.
	secretNames, err := env.FilterNames(allNames, only, except)
	if err != nil {
		h.recordAudit("mcp:exec", command, "all", false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to filter secrets: %s", err)), nil
	}

	// Enforce scoped policy before reading any secret values.
	if err := h.getPolicy().Check(command, secretNames); err != nil {
		h.recordAudit("mcp:exec", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Token or approval gateway
	tokenID := request.GetString("token", "")
	if err := h.checkTokenOrApproval(ctx, tokenID, command, secretNames, approval.FormatArgs(args)); err != nil {
		h.recordAudit("mcp:exec:approval", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Fetch values only for the secrets that survived filtering and policy.
	secrets := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		val, err := store.Get(name)
		if err != nil {
			h.recordAudit("mcp:exec", command, strings.Join(secretNames, ","), false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to get secret %q: %s", name, err)), nil
		}
		secrets[name] = val
	}
	defer sensitive.ClearMap(secrets)

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
	output = truncateOutput(output, MaxOutputBytes)

	// Build result text
	exitCode := 0
	if execErr != nil {
		if exitError, ok := execErr.(*osexec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			h.recordAudit("mcp:exec", command, "all", false, "timeout")
			return mcp.NewToolResultError(fmt.Sprintf("command timed out after %d seconds", timeoutSecs)), nil
		} else {
			h.recordAudit("mcp:exec", command, "all", false, execErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to execute command: %s", execErr)), nil
		}
	}

	// Record audit
	errMsg := ""
	if execErr != nil {
		errMsg = execErr.Error()
	}
	h.recordAudit("mcp:exec", command, strings.Join(secretNames, ","), execErr == nil, errMsg)

	resultText := string(output)
	if exitCode != 0 {
		resultText = fmt.Sprintf("[exit code: %d]\n%s", exitCode, resultText)
	}

	return mcp.NewToolResultText(resultText), nil
}

func (h *Handler) HandleExecWithSecrets(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command := strings.TrimSpace(request.GetString("command", ""))
	if command == "" {
		return mcp.NewToolResultError("parameter 'command' is required"), nil
	}
	if strings.Contains(command, "..") {
		return mcp.NewToolResultError("command must not contain '..' (path traversal)"), nil
	}

	// Reject placeholders in command — secret values must not control which binary runs
	if placeholder.ContainsPlaceholder(command) {
		return mcp.NewToolResultError("placeholders are not allowed in 'command' — use them only in 'args'"), nil
	}

	args := request.GetStringSlice("args", nil)

	timeoutSecs := request.GetInt("timeout_seconds", DefaultTimeoutSecs)
	if timeoutSecs <= 0 {
		timeoutSecs = DefaultTimeoutSecs
	}
	if timeoutSecs > MaxTimeoutSecs {
		timeoutSecs = MaxTimeoutSecs
	}

	// Extract referenced secret names from args
	secretNames := placeholder.Extract("", args)

	// Enforce scoped policy before touching the keyring
	if err := h.getPolicy().Check(command, secretNames); err != nil {
		h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	store, err := h.getStore()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}

	// Don't ask the user to approve secrets that don't exist.
	if err := requireSecretsExist(store, secretNames); err != nil {
		h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Token or approval gateway. The prompt shows args with placeholders
	// unresolved, so the user sees where each secret is going.
	tokenID := request.GetString("token", "")
	if err := h.checkTokenOrApproval(ctx, tokenID, command, secretNames, approval.FormatArgs(args)); err != nil {
		h.recordAudit("mcp:exec_with_secrets:approval", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Fetch only the secrets that are actually referenced
	secrets := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		val, err := store.Get(name)
		if err != nil {
			h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to get secret %q: %s", name, err)), nil
		}
		secrets[name] = val
	}
	defer sensitive.ClearMap(secrets)

	// Resolve placeholders in args
	resolvedArgs, err := placeholder.Resolve(args, secrets)
	if err != nil {
		h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
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
	output = truncateOutput(output, MaxOutputBytes)

	exitCode := 0
	if execErr != nil {
		if exitError, ok := execErr.(*osexec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, "timeout")
			return mcp.NewToolResultError(fmt.Sprintf("command timed out after %d seconds", timeoutSecs)), nil
		} else {
			h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, execErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("failed to execute command: %s", execErr)), nil
		}
	}

	errMsg := ""
	if execErr != nil {
		errMsg = execErr.Error()
	}
	h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), execErr == nil, errMsg)

	resultText := string(output)
	if exitCode != 0 {
		resultText = fmt.Sprintf("[exit code: %d]\n%s", exitCode, resultText)
	}

	return mcp.NewToolResultText(resultText), nil
}

func (h *Handler) HandleMintToken(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	secrets := request.GetStringSlice("secrets", nil)
	if len(secrets) == 0 {
		return mcp.NewToolResultError("parameter 'secrets' is required and must be non-empty"), nil
	}

	ttlSecs := request.GetInt("ttl_seconds", 0)
	maxUses := request.GetInt("max_uses", 0)
	mintedFor := request.GetString("for", "*")

	mintReq := token.MintRequest{
		Secrets:   secrets,
		TTLSecs:   ttlSecs,
		MaxUses:   maxUses,
		MintedFor: mintedFor,
	}

	// Reject anything Mint would refuse before prompting, so the user is
	// never asked to approve a token that can't be created.
	if err := mintReq.Validate(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to mint token: %s", err)), nil
	}
	store, err := h.getStore()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to open keyring: %s", err)), nil
	}
	if err := requireSecretsExist(store, secrets); err != nil {
		h.recordAudit("mcp:mint_token", "mint_token", strings.Join(secrets, ","), false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to mint token: %s", err)), nil
	}

	usesStr := "unlimited"
	if maxUses > 0 {
		usesStr = fmt.Sprintf("%d", maxUses)
	}

	// Minting always requires approval — this is the one-time consent gate.
	detail := fmt.Sprintf("token for=%s, ttl=%ds, max_uses=%s", approval.Quote(mintedFor), ttlSecs, usesStr)
	if err := h.approvalFn(ctx, h.mcpSrv, "mint_token", secrets, detail); err != nil {
		h.recordAudit("mcp:mint_token:approval", "mint_token", strings.Join(secrets, ","), false, err.Error())
		return mcp.NewToolResultError(err.Error()), nil
	}
	h.recordAudit("mcp:mint_token:approval", "mint_token", strings.Join(secrets, ","), true, "")

	tok, err := h.tokenStore.Mint(mintReq)
	if err != nil {
		h.recordAudit("mcp:mint_token", "mint_token", strings.Join(secrets, ","), false, err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to mint token: %s", err)), nil
	}

	h.recordAudit("mcp:mint_token", "mint_token", strings.Join(secrets, ","), true, "")

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

func (h *Handler) HandleRevokeToken(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokenID := request.GetString("token_id", "")
	if tokenID == "" {
		return mcp.NewToolResultError("parameter 'token_id' is required"), nil
	}

	if h.tokenStore.Revoke(tokenID) {
		h.recordAudit("mcp:revoke_token", "revoke_token", tokenID, true, "")
		return mcp.NewToolResultText("Token revoked."), nil
	}

	h.recordAudit("mcp:revoke_token", "revoke_token", tokenID, false, "not found")
	return mcp.NewToolResultError("token not found"), nil
}

func (h *Handler) HandleListTokens(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tokens := h.tokenStore.List()

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
func (h *Handler) checkTokenOrApproval(ctx context.Context, tokenID, command string, secretNames []string, detail string) error {
	if tokenID != "" {
		result := h.tokenStore.UseFor(tokenID, command, secretNames)
		if result.Valid {
			h.recordAudit("mcp:token_use", command, strings.Join(secretNames, ","), true, "")
			return nil
		}
		return tokenInvalid(result, command)
	}

	// Try cached session token (auto-minted).
	if h.useSessionToken(secretNames) {
		h.recordAudit("mcp:token_use", command, strings.Join(secretNames, ","), true, "")
		return nil
	}

	// No token provided — check if policy requires one. Snapshot the
	// current policy once so the token-required and approval checks see a
	// consistent view even if the file is rewritten mid-request.
	pol := h.getPolicy()
	if pol.RequiresToken(command, secretNames) {
		return fmt.Errorf("token required by policy — use mint_token to create an access lease")
	}

	// Auto-mint: one approval covers the rest of the session.
	if h.cfg != nil && h.cfg.Auth.AutoMintToken {
		if err := h.tryAutoMint(ctx, secretNames); err == nil {
			return nil
		}
		// Auto-mint declined or failed — fall through to per-call approval.
	}

	// Fall through to existing approval gateway.
	if pol.RequiresApproval(command, secretNames) {
		if err := h.approvalFn(ctx, h.mcpSrv, command, secretNames, detail); err != nil {
			return fmt.Errorf("approval denied: %w", err)
		}
	}

	return nil
}

// tokenInvalid explains why a token was refused for command.
func tokenInvalid(result token.ValidationResult, command string) error {
	if result.Reason == "wrong_command" {
		return fmt.Errorf("token invalid: wrong_command: it was minted for %q, which does not match %q",
			result.MintedFor, filepath.Base(command))
	}
	return fmt.Errorf("token invalid: %s", result.Reason)
}

// useSessionToken reports whether the cached session token covers
// secretNames, clearing it if it has expired or doesn't.
func (h *Handler) useSessionToken(secretNames []string) bool {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	return h.validSessionTokenLocked(secretNames)
}

// validSessionTokenLocked is useSessionToken for callers holding sessionMu.
func (h *Handler) validSessionTokenLocked(secretNames []string) bool {
	if h.sessionTokenID == "" {
		return false
	}
	if h.tokenStore.Validate(h.sessionTokenID, secretNames).Valid {
		return true
	}
	h.sessionTokenID = ""
	return false
}

// tryAutoMint requests a one-time approval to mint a session token covering
// all secrets. Only one mint runs at a time; a call that arrives during one
// waits for it, for no longer than its own context allows, and takes its
// result.
func (h *Handler) tryAutoMint(ctx context.Context, secretNames []string) error {
	for {
		h.sessionMu.Lock()
		if h.validSessionTokenLocked(secretNames) {
			h.sessionMu.Unlock()
			return nil
		}
		if call := h.minting; call != nil {
			h.sessionMu.Unlock()
			select {
			case <-call.done:
				if call.err != nil {
					return call.err
				}
				continue // re-check: the new token may not cover secretNames
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		call := &mintCall{done: make(chan struct{})}
		h.minting = call
		h.sessionMu.Unlock()
		return h.leadMint(ctx, call, secretNames)
	}
}

// leadMint runs the mint for call and then releases it, even if the prompt
// panics: WithRecovery keeps the server alive after a panic, and a mint
// left in flight would make every later call wait on it.
func (h *Handler) leadMint(ctx context.Context, call *mintCall, secretNames []string) error {
	call.err = fmt.Errorf("auto-mint did not complete")
	defer func() {
		h.sessionMu.Lock()
		h.minting = nil
		h.sessionMu.Unlock()
		close(call.done)
	}()
	call.err = h.mintSessionToken(ctx, secretNames)
	return call.err
}

// mintSessionToken prompts for and mints the session token. The caller
// owns h.minting.
func (h *Handler) mintSessionToken(ctx context.Context, secretNames []string) error {
	// Gather all secret names so the token covers everything.
	store, err := h.getStore()
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

	promptCtx, cancel := context.WithTimeout(ctx, autoMintPromptTimeout)
	defer cancel()
	if err := h.approvalFn(promptCtx, h.mcpSrv, "session_token", allNames, "session token: unlimited uses, 1h, any command"); err != nil {
		return err
	}

	tok, err := h.tokenStore.Mint(token.MintRequest{
		Secrets:   allNames,
		TTLSecs:   AutoMintTTLSecs,
		MaxUses:   0, // unlimited
		MintedFor: "*",
	})
	if err != nil {
		return err
	}

	h.sessionMu.Lock()
	h.sessionTokenID = tok.ID
	h.sessionMu.Unlock()
	h.recordAudit("mcp:auto_mint", "session_token", strings.Join(allNames, ","), true, "")
	return nil
}

// requireSecretsExist returns an error naming any of names that isn't stored.
func requireSecretsExist(store SecretStore, names []string) error {
	stored, err := store.List()
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}
	have := make(map[string]bool, len(stored))
	for _, n := range stored {
		have[n] = true
	}
	for _, n := range names {
		if !have[n] {
			return fmt.Errorf("failed to get secret %q: not found", n)
		}
	}
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

// validateFilterNames validates that only/except filter values contain valid secret names.
func validateFilterNames(only, except string) error {
	for _, raw := range []string{only, except} {
		if raw == "" {
			continue
		}
		for _, name := range env.ParseCommaSeparated(raw) {
			if err := nokeyKeyring.ValidateSecretName(name); err != nil {
				return fmt.Errorf("invalid filter name %q: %w", name, err)
			}
		}
	}
	return nil
}

// recordAudit delegates to the injected audit function.
func (h *Handler) recordAudit(operation, command, target string, success bool, errMsg string) {
	h.auditFn(operation, command, target, success, errMsg)
}
