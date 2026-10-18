package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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

	// Annotations: mcp-go's NewTool defaults every tool to destructive and
	// open-world, so each tool states the hints that differ.

	// list_secrets — read-only, AI needs to know available secret names
	s.AddTool(
		mcp.NewTool("list_secrets",
			mcp.WithDescription("List all stored secret key names (not values)"),
			mcp.WithTitleAnnotation("List secret names"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
		),
		h.HandleListSecrets,
	)

	// exec — run a command with secrets injected, output always redacted
	s.AddTool(
		mcp.NewTool("exec",
			mcp.WithDescription("Execute a command with secrets injected as environment variables. Output is automatically redacted — secret values are replaced with [REDACTED:KEY_NAME]."),
			mcp.WithTitleAnnotation("Run command with secrets in env"),
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
			mcp.WithString("cwd",
				mcp.Description("Absolute path of an existing directory to run in (default: the server's working directory). The command must then be a bare name or an absolute path."),
			),
			mcp.WithString("stdin",
				mcp.Description("Text written to the command's standard input (default: none)"),
			),
			mcp.WithObject("env",
				mcp.Description("Extra non-secret environment variables, as {\"NAME\": \"value\"}. Rejected: names of stored secrets, and variables that change what code runs (PATH, LD_*, DYLD_*, BASH_ENV, NODE_OPTIONS, PYTHON*, GIT_SSH*, ...)."),
				mcp.AdditionalProperties(map[string]any{"type": "string"}),
			),
			mcp.WithBoolean("separate_stderr",
				mcp.Description("Return stderr after stdout, under a [stderr] line, instead of interleaved (default: false)"),
			),
			mcp.WithString("token",
				mcp.Description("Access lease token ID. If valid, skips the approval prompt."),
			),
			mcp.WithOutputSchema[execOutput](),
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
			mcp.WithTitleAnnotation("Run command with secret placeholders"),
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
			mcp.WithString("cwd",
				mcp.Description("Absolute path of an existing directory to run in (default: the server's working directory). The command must then be a bare name or an absolute path."),
			),
			mcp.WithString("stdin",
				mcp.Description("Text written to the command's standard input (default: none)"),
			),
			mcp.WithObject("env",
				mcp.Description("Extra non-secret environment variables, as {\"NAME\": \"value\"}. Rejected: names of stored secrets, and variables that change what code runs (PATH, LD_*, DYLD_*, BASH_ENV, NODE_OPTIONS, PYTHON*, GIT_SSH*, ...)."),
				mcp.AdditionalProperties(map[string]any{"type": "string"}),
			),
			mcp.WithBoolean("separate_stderr",
				mcp.Description("Return stderr after stdout, under a [stderr] line, instead of interleaved (default: false)"),
			),
			mcp.WithString("token",
				mcp.Description("Access lease token ID. If valid, skips the approval prompt."),
			),
			mcp.WithOutputSchema[execOutput](),
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
			mcp.WithTitleAnnotation("Mint access token"),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithOpenWorldHintAnnotation(false),
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
			mcp.WithTitleAnnotation("Revoke access token"),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
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
			mcp.WithTitleAnnotation("List access tokens"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
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
			// Idempotent: a second call returns the running proxy's address.
			mcp.WithTitleAnnotation("Start secret-injecting proxy"),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
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
			mcp.WithTitleAnnotation("Stop proxy"),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
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

	//nolint:contextcheck // proxy lifetime is the MCP session, not this request
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

func (h *Handler) HandleStopProxy(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h.proxyMu.Lock()
	defer h.proxyMu.Unlock()

	if h.proxyServer == nil {
		return mcp.NewToolResultText("No proxy running."), nil
	}

	// WithoutCancel: a client cancelling the call must not cut the graceful
	// shutdown short.
	if err := h.proxyServer.Stop(context.WithoutCancel(ctx)); err != nil {
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

	args, err := argsParam(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	opts, err := execOptionsParam(request, command)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	only := request.GetString("only", "")
	except := request.GetString("except", "")

	// Validate only/except filter names
	if err := validateFilterNames(only, except); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	timeoutSecs, clamped := timeoutParam(request)

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
	if err := checkEnvNotSecret(opts.env, allNames); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
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
		return mcp.NewToolResultError(h.policyDenialText(err)), nil
	}

	// Token or approval gateway
	tokenID := request.GetString("token", "")
	if err := h.checkTokenOrApproval(ctx, tokenID, command, secretNames, execDetail(args, opts)); err != nil {
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

	res := runRedacted(ctx, runSpec{
		command: command,
		args:    args,
		env:     env.MergeEnvironment(env.MergeEnvironment(os.Environ(), opts.env), secrets),
		secrets: secrets,
		timeout: time.Duration(timeoutSecs) * time.Second,
		opts:    opts,
	})
	return h.execOutcome("mcp:exec", command, secretNames, timeoutSecs, clamped, res), nil
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

	args, err := argsParam(request)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	opts, err := execOptionsParam(request, command)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	timeoutSecs, clamped := timeoutParam(request)

	// Extract referenced secret names from args
	secretNames := placeholder.Extract("", args)

	// Enforce scoped policy before touching the keyring
	if err := h.getPolicy().Check(command, secretNames); err != nil {
		h.recordAudit("mcp:exec_with_secrets", command, strings.Join(secretNames, ","), false, err.Error())
		return mcp.NewToolResultError(h.policyDenialText(err)), nil
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
	if len(opts.env) > 0 {
		stored, err := store.List()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list secrets: %s", err)), nil
		}
		if err := checkEnvNotSecret(opts.env, stored); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	// Token or approval gateway. The prompt shows args with placeholders
	// unresolved, so the user sees where each secret is going.
	tokenID := request.GetString("token", "")
	if err := h.checkTokenOrApproval(ctx, tokenID, command, secretNames, execDetail(args, opts)); err != nil {
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
	res := runRedacted(ctx, runSpec{
		command: command,
		args:    resolvedArgs,
		env:     env.MergeEnvironment(os.Environ(), opts.env),
		secrets: secrets,
		timeout: time.Duration(timeoutSecs) * time.Second,
		opts:    opts,
	})
	return h.execOutcome("mcp:exec_with_secrets", command, secretNames, timeoutSecs, clamped, res), nil
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

	// The audit log outlives the token, but a live ID is a bearer
	// credential, so record only a fingerprint of it.
	if h.tokenStore.Revoke(tokenID) {
		h.recordAudit("mcp:revoke_token", "revoke_token", tokenFingerprint(tokenID), true, "")
		return mcp.NewToolResultText("Token revoked."), nil
	}

	h.recordAudit("mcp:revoke_token", "revoke_token", tokenFingerprint(tokenID), false, "not found")
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
		names, _ := json.Marshal(secretNames)
		base := filepath.Base(command)
		return fmt.Errorf("token required by policy for %q: call mint_token with secrets %s and for %q, then pass the returned ID as the token parameter", base, names, base)
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

// argsParam reads the "args" parameter. exec's schema declares it as a
// string holding a JSON array, so that form is accepted alongside a plain
// array; GetStringSlice alone silently drops a string.
func argsParam(request mcp.CallToolRequest) ([]string, error) {
	raw, ok := request.GetArguments()["args"].(string)
	if !ok {
		return request.GetStringSlice("args", nil), nil
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return nil, fmt.Errorf("parameter 'args' must be a JSON array of strings: %w", err)
	}
	return args, nil
}

// timeoutParam reads timeout_seconds, defaulting non-positive values and
// clamping to MaxTimeoutSecs. clamped reports that the caller asked for
// more than the maximum, so the result can say so.
func timeoutParam(request mcp.CallToolRequest) (secs int, clamped bool) {
	secs = request.GetInt("timeout_seconds", DefaultTimeoutSecs)
	if secs <= 0 {
		secs = DefaultTimeoutSecs
	}
	if secs > MaxTimeoutSecs {
		return MaxTimeoutSecs, true
	}
	return secs, false
}

// execOptions are the optional parameters both exec tools accept. The
// zero value runs as before they existed.
type execOptions struct {
	dir            string
	stdin          string
	env            map[string]string // non-secret extras
	separateStderr bool
}

// envNameRe is a portable environment variable name.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Environment variables that make a program load, run or look up other
// code. Approving a command means approving that program, so the caller
// may not set these. Matched case-insensitively, since Windows names are.
var (
	reservedEnvNames = []string{
		"PATH", "BASH_ENV", "ENV", "IFS", "NODE_OPTIONS", "NODE_PATH",
		"GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_PROXY_COMMAND", "GIT_PAGER",
		"SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND",
		"PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "LESSOPEN", "LESSCLOSE",
		"GOFLAGS", "CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
	}
	reservedEnvPrefixes = []string{
		"LD_", "DYLD_", "PYTHON", "PERL5", "RUBY", "GIT_SSH", "GIT_CONFIG",
		"DOTNET_", "NPM_CONFIG_",
	}
)

// reservedEnvName reports whether name is one the caller may not set.
func reservedEnvName(name string) bool {
	upper := strings.ToUpper(name)
	if slices.Contains(reservedEnvNames, upper) {
		return true
	}
	for _, prefix := range reservedEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// execOptionsParam reads and validates cwd, stdin, env and separate_stderr.
// command is the command being run, which cwd must not change the meaning
// of.
func execOptionsParam(request mcp.CallToolRequest, command string) (execOptions, error) {
	opts := execOptions{
		dir:            request.GetString("cwd", ""),
		stdin:          request.GetString("stdin", ""),
		separateStderr: request.GetBool("separate_stderr", false),
	}

	if opts.dir != "" {
		if !filepath.IsAbs(opts.dir) {
			return opts, fmt.Errorf("parameter 'cwd' must be an absolute path")
		}
		if slices.Contains(strings.Split(filepath.ToSlash(opts.dir), "/"), "..") {
			return opts, fmt.Errorf("parameter 'cwd' must not contain '..' (path traversal)")
		}
		if info, err := os.Stat(opts.dir); err != nil || !info.IsDir() {
			return opts, fmt.Errorf("parameter 'cwd' must be an existing directory")
		}
		// A relative path would resolve inside the directory the caller
		// just chose: cwd=/tmp/x with ./gh still matches a "gh" rule.
		if !filepath.IsAbs(command) && strings.ContainsAny(command, `/\`) {
			return opts, fmt.Errorf("parameter 'cwd' cannot be used with a relative command path; use a bare name or an absolute path")
		}
	}

	if raw := request.GetArguments()["env"]; raw != nil {
		vars, ok := raw.(map[string]any)
		if !ok {
			return opts, fmt.Errorf("parameter 'env' must be an object of string values")
		}
		opts.env = make(map[string]string, len(vars))
		for name, v := range vars {
			if !envNameRe.MatchString(name) {
				return opts, fmt.Errorf("parameter 'env' has an invalid variable name %q", name)
			}
			if reservedEnvName(name) {
				return opts, fmt.Errorf("parameter 'env' must not set %q: it changes which code the command loads or runs", name)
			}
			value, ok := v.(string)
			if !ok {
				return opts, fmt.Errorf("parameter 'env' value for %q must be a string", name)
			}
			opts.env[name] = value
		}
	}

	return opts, nil
}

// execDetail is the approval-prompt detail for an exec call: everything
// besides the command and secrets that decides what will run.
func execDetail(args []string, opts execOptions) string {
	var lines []string
	if a := approval.FormatArgs(args); a != "" {
		lines = append(lines, a)
	}
	if opts.dir != "" {
		lines = append(lines, "cwd: "+approval.Quote(opts.dir))
	}
	if e := approval.FormatEnv(opts.env); e != "" {
		lines = append(lines, e)
	}
	if in := approval.FormatStdin(opts.stdin); in != "" {
		lines = append(lines, in)
	}
	return strings.Join(lines, "\n")
}

// envNamesFoldCase is whether environment names are case-insensitive, as
// they are on Windows. A var so tests can exercise both.
var envNamesFoldCase = runtime.GOOS == "windows"

// checkEnvNotSecret rejects extra env entries named after a stored secret.
// They would shadow or impersonate the real secret, and their values,
// unlike secrets, are not redacted.
func checkEnvNotSecret(extra map[string]string, stored []string) error {
	for _, name := range stored {
		for key := range extra {
			if key == name || (envNamesFoldCase && strings.EqualFold(key, name)) {
				return fmt.Errorf("parameter 'env' must not set %q: that is the name of a stored secret", key)
			}
		}
	}
	return nil
}

// runSpec describes a command for runRedacted.
type runSpec struct {
	command string
	args    []string
	env     []string
	secrets map[string]string // values redacted from the output
	timeout time.Duration
	opts    execOptions
}

// runResult is what runRedacted observed. output and stderr are already
// redacted and truncated, so they are safe to return to the model. stderr
// is set only when it was captured separately.
type runResult struct {
	output        []byte
	stderr        []byte
	err           error
	timedOut      bool
	truncated     bool  // some output was cut
	originalBytes int64 // everything the command wrote, both streams
}

// text renders the output for the tool result.
func (res runResult) text() string {
	out := string(res.output)
	if len(res.stderr) > 0 {
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += "[stderr]\n" + string(res.stderr)
	}
	return out
}

// killWaitDelay bounds how long a run may outlive its timeout while
// something still holds the output pipe open.
const killWaitDelay = 2 * time.Second

// runRedacted runs spec and returns its redacted output. The child gets no
// stdin unless the caller supplied some: the server's own stdin is the MCP
// JSON-RPC transport.
func runRedacted(ctx context.Context, spec runSpec) runResult {
	execCtx, cancel := context.WithTimeout(ctx, spec.timeout)
	defer cancel()

	cmd := osexec.CommandContext(execCtx, spec.command, spec.args...)
	cmd.Env = spec.env
	cmd.Dir = spec.opts.dir
	if spec.opts.stdin != "" {
		cmd.Stdin = strings.NewReader(spec.opts.stdin)
	}
	// On timeout kill the whole process tree, not just the direct child:
	// a background grandchild would otherwise keep the pipe open and the
	// read blocked. WaitDelay is the backstop where that isn't possible.
	killProcessTreeOnCancel(cmd)
	cmd.WaitDelay = killWaitDelay

	// Keep only what can reach the result instead of buffering everything
	// the command prints. The same writer for both streams preserves
	// CombinedOutput's interleaving.
	// Split streams share the output budget, half each, so the result is
	// no larger than when they are interleaved.
	budget := MaxOutputBytes
	if spec.opts.separateStderr {
		budget /= 2
	}
	buf := newCappedBuffer(budget, spec.secrets)
	cmd.Stdout = buf
	cmd.Stderr = buf
	var errBuf *cappedBuffer
	if spec.opts.separateStderr {
		errBuf = newCappedBuffer(budget, spec.secrets)
		cmd.Stderr = errBuf
	}
	err := cmd.Run()
	// ErrWaitDelay means the command exited 0 but something it started
	// still held the output open (a daemonised child, say). The run itself
	// finished, so keep its output rather than calling it a failure.
	if errors.Is(err, osexec.ErrWaitDelay) {
		err = nil
	}

	res := runResult{
		err:           err,
		timedOut:      errors.Is(execCtx.Err(), context.DeadlineExceeded),
		originalBytes: buf.total,
	}
	res.output, res.truncated = redactCaptured(buf, spec.secrets)
	if errBuf != nil {
		var cut bool
		res.stderr, cut = redactCaptured(errBuf, spec.secrets)
		res.truncated = res.truncated || cut
		res.originalBytes += errBuf.total
	}
	return res
}

// redactCaptured returns the redacted, truncated contents of b and zeroes
// the raw bytes. It clones first: with nothing to replace, redaction and
// truncation return the raw buffer itself.
func redactCaptured(b *cappedBuffer, secrets map[string]string) (out []byte, truncated bool) {
	out, truncated = capOutput(b, secrets)
	out = bytes.Clone(out)
	sensitive.ClearBytes(b.buf)
	return out, truncated
}

// cappedBuffer is an io.Writer that keeps the first limit bytes written and
// counts the rest. It never fails a write, so the child isn't killed by
// SIGPIPE or a short write when its output runs long.
type cappedBuffer struct {
	buf   []byte
	max   int // output size after redaction and truncation
	limit int // bytes kept: max plus redactSlack
	total int64
}

// newCappedBuffer returns a cappedBuffer whose redacted output fits in size.
func newCappedBuffer(size int, secrets map[string]string) *cappedBuffer {
	return &cappedBuffer{max: size, limit: size + redactSlack(secrets)}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	if room := b.limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// overflowed reports whether output was dropped.
func (b *cappedBuffer) overflowed() bool {
	return b.total > int64(len(b.buf))
}

// redactSlack is how far past MaxOutputBytes a cappedBuffer keeps, so that
// a secret straddling the MaxOutputBytes mark is still whole and gets
// redacted exactly as it would have been in the full output. It is a
// generous bound on the longest form redact matches: the value, its
// base64/hex/URL encodings, or a JSON \uXXXX escape at 6 bytes per byte.
func redactSlack(secrets map[string]string) int {
	longest := 0
	for _, v := range secrets {
		longest = max(longest, len(v))
	}
	return 6*longest + 4
}

// capOutput redacts and truncates what a cappedBuffer kept, reporting
// whether anything was cut. Output that fit is treated exactly as before
// the cap existed.
func capOutput(b *cappedBuffer, secrets map[string]string) ([]byte, bool) {
	out := redact.RedactBytes(b.buf, secrets)
	if !b.overflowed() {
		return truncateOutput(out, b.max), len(out) > b.max
	}
	// The cap may have cut a secret, or an encoding of one, leaving a
	// prefix that redaction can't recognise. That fragment is unchanged by
	// redaction and sits in the last redactSlack-1 bytes, so drop them.
	// Redaction can also shrink the output below MaxOutputBytes, so the
	// truncation notice is added explicitly rather than by length.
	drop := min(redactSlack(secrets)-1, len(out))
	return withTruncationNotice(out[:len(out)-drop], b.max), true
}

// exitCode returns the exit status carried by err, if it has one.
func exitCode(err error) (int, bool) {
	var exitErr *osexec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), true
	}
	return 0, false
}

// execOutput is the structured result of the exec tools, sent alongside
// the same text content they have always returned.
type execOutput struct {
	Output          string   `json:"output" jsonschema_description:"Redacted output; stdout only when separate_stderr is set"`
	Stderr          string   `json:"stderr,omitempty" jsonschema_description:"Redacted stderr, when separate_stderr is set"`
	ExitCode        int      `json:"exit_code"`
	TimedOut        bool     `json:"timed_out"`
	Truncated       bool     `json:"truncated" jsonschema_description:"Output was cut to fit the size limit"`
	OriginalBytes   int64    `json:"original_bytes" jsonschema_description:"Bytes the command wrote before redaction and truncation"`
	SecretsInjected []string `json:"secrets_injected" jsonschema_description:"Names of the secrets the command was given"`
}

// execOutcome records the audit entry for a finished run and builds the
// tool result.
func (h *Handler) execOutcome(op, command string, secretNames []string, timeoutSecs int, clamped bool, res runResult) *mcp.CallToolResult {
	target := strings.Join(secretNames, ",")
	note := ""
	if clamped {
		note = fmt.Sprintf("[timeout_seconds clamped to %d]\n", MaxTimeoutSecs)
	}
	code, exited := exitCode(res.err)
	structured := execOutput{
		Output:          string(res.output),
		Stderr:          string(res.stderr),
		ExitCode:        code,
		TimedOut:        res.timedOut,
		Truncated:       res.truncated,
		OriginalBytes:   res.originalBytes,
		SecretsInjected: append([]string{}, secretNames...),
	}

	// Check the deadline first: a child killed by it reports an ExitError
	// ("signal: killed"), which would otherwise read as an ordinary exit.
	if res.timedOut {
		h.recordAudit(op, command, target, false, "timeout")
		result := mcp.NewToolResultError(fmt.Sprintf("command timed out after %d seconds\n%s%s", timeoutSecs, note, res.text()))
		result.StructuredContent = structured
		return result
	}

	if res.err != nil && !exited {
		h.recordAudit(op, command, target, false, res.err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("failed to execute command: %s", res.err))
	}

	errMsg := ""
	if res.err != nil {
		errMsg = res.err.Error()
	}
	h.recordAudit(op, command, target, res.err == nil, errMsg)

	resultText := res.text()
	if code != 0 {
		resultText = fmt.Sprintf("[exit code: %d]\n%s", code, resultText)
	}
	return mcp.NewToolResultStructured(structured, note+resultText)
}

// policyDenialText is err's message, followed for a policy denial by how
// the user can allow the call.
func (h *Handler) policyDenialText(err error) string {
	var denial *policy.Denial
	if !errors.As(err, &denial) {
		return err.Error()
	}
	path := ""
	if h.getConfigDir != nil {
		if dir, dirErr := h.getConfigDir(); dirErr == nil {
			path = filepath.Join(dir, "policies.yaml")
		}
	}
	return err.Error() + "\n\n" + denial.Hint(path)
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

// tokenFingerprint identifies a token ID in the audit log without recording
// the ID itself.
func tokenFingerprint(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "sha256:" + hex.EncodeToString(sum[:6])
}

// truncationNotice ends output that was cut short.
const truncationNotice = "\n\n[output truncated]"

// truncateOutput truncates output to maxBytes, appending a truncation notice.
func truncateOutput(data []byte, maxBytes int) []byte {
	if len(data) <= maxBytes {
		return data
	}
	return withTruncationNotice(data, maxBytes)
}

// withTruncationNotice returns data, cut if necessary, followed by the
// truncation notice, in at most maxBytes.
func withTruncationNotice(data []byte, maxBytes int) []byte {
	keep := min(len(data), maxBytes-len(truncationNotice))
	truncated := make([]byte, keep+len(truncationNotice))
	copy(truncated, data[:keep])
	copy(truncated[keep:], truncationNotice)
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
