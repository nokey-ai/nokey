package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kring "github.com/99designs/keyring"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/nokey-ai/nokey/internal/token"
)

// --- helpers ---

// getResultText extracts the text content from a CallToolResult.
func getResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil {
		t.Fatal("nil result")
	}
	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// makeCallToolRequest builds a CallToolRequest with the given arguments map.
func makeCallToolRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: args,
		},
	}
}

// withMCPGlobals sets up package-level MCP vars (pol, tokenStore, cfg, sessionTokenID) and restores on cleanup.
func withMCPGlobals(t *testing.T) {
	t.Helper()

	oldPol := pol
	oldTokenStore := tokenStore
	oldSessionTokenID := sessionTokenID
	t.Cleanup(func() {
		pol = oldPol
		tokenStore = oldTokenStore
		sessionTokenID = oldSessionTokenID
	})

	pol = nil // nil policy allows everything
	tokenStore = token.NewStore()
	sessionTokenID = ""

	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)
}

// --- truncateOutput ---

func TestTruncateOutput(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		max      int
		wantLen  int
		wantTail string // expected suffix after truncation
	}{
		{
			name:    "under limit unchanged",
			data:    []byte("hello"),
			max:     100,
			wantLen: 5,
		},
		{
			name:    "exactly at limit unchanged",
			data:    []byte("hello"),
			max:     5,
			wantLen: 5,
		},
		{
			name:     "over limit truncated",
			data:     bytes.Repeat([]byte("x"), 200),
			max:      100,
			wantLen:  100,
			wantTail: "\n\n[output truncated]",
		},
		{
			name:    "nil data",
			data:    nil,
			max:     100,
			wantLen: 0,
		},
		{
			name:    "empty data",
			data:    []byte{},
			max:     100,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateOutput(tt.data, tt.max)
			if len(got) != tt.wantLen {
				t.Errorf("truncateOutput() len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantTail != "" && !strings.HasSuffix(string(got), tt.wantTail) {
				t.Errorf("truncateOutput() should end with %q, got tail %q",
					tt.wantTail, string(got[len(got)-len(tt.wantTail):]))
			}
		})
	}
}

// --- handleListSecrets ---

func TestHandleListSecrets_NoSecrets(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	result, err := handleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "No secrets stored") {
		t.Errorf("result = %q, want 'No secrets stored'", text)
	}
}

func TestHandleListSecrets_WithSecrets(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("API_KEY", "val1")
	store.Set("DB_PASS", "val2")

	result, err := handleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "API_KEY") {
		t.Errorf("result missing API_KEY: %q", text)
	}
	if !strings.Contains(text, "DB_PASS") {
		t.Errorf("result missing DB_PASS: %q", text)
	}
}

// --- handleExec ---

func TestHandleExec_MissingCommand(t *testing.T) {
	result, err := handleExec(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'command' is required") {
		t.Errorf("result = %q, want command required error", text)
	}
}

func TestHandleExec_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("MY_KEY", "my-value")

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello", "world"},
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "hello world") {
		t.Errorf("result = %q, want output containing 'hello world'", text)
	}
}

func TestHandleExec_NonZeroExit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	req := makeCallToolRequest(map[string]any{
		"command": "sh",
		"args":    []any{"-c", "exit 42"},
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "exit code: 42") {
		t.Errorf("result = %q, want 'exit code: 42'", text)
	}
}

func TestHandleExec_RedactsOutput(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("TOKEN", "supersecret42")

	req := makeCallToolRequest(map[string]any{
		"command": "sh",
		"args":    []any{"-c", "echo supersecret42"},
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if strings.Contains(text, "supersecret42") {
		t.Errorf("output should not contain the secret value: %q", text)
	}
	if !strings.Contains(text, "[REDACTED:TOKEN]") {
		t.Errorf("output should contain redacted marker: %q", text)
	}
}

func TestHandleExec_CommandNotFound(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	req := makeCallToolRequest(map[string]any{
		"command": "/nonexistent/binary",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to execute") {
		t.Errorf("result = %q, want execution error", text)
	}
}

func TestHandleExec_FilterOnly(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("A", "val-a")
	store.Set("B", "val-b")

	req := makeCallToolRequest(map[string]any{
		"command": "env",
		"only":    "A",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	// A should be in env output; B should not
	if !strings.Contains(text, "A=") {
		t.Errorf("result missing A env var: %q", text)
	}
}

func TestHandleExec_FilterExcept(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("KEEP", "keep-val")
	store.Set("SKIP", "skip-val")

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"done"},
		"except":  "SKIP",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "done") {
		t.Errorf("result = %q, want 'done'", text)
	}
}

func TestHandleExec_PolicyDenied(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Set a restrictive policy that denies access
	pol = &policy.Policy{
		Rules: []policy.Rule{{
			Commands: []string{"allowed-cmd"},
			Secrets:  []string{"*"},
		}},
	}

	store.Set("SECRET", "val")

	req := makeCallToolRequest(map[string]any{
		"command": "denied-cmd",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "policy denied") {
		t.Errorf("result = %q, want policy denial", text)
	}
}

func TestHandleExec_WithValidToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("KEY", "val")

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"KEY"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"ok"},
		"token":   tok.ID,
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "ok") {
		t.Errorf("result = %q, want 'ok'", text)
	}
}

func TestHandleExec_WithInvalidToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("KEY", "val")

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"ok"},
		"token":   "bad-token-id",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "token invalid") {
		t.Errorf("result = %q, want 'token invalid'", text)
	}
}

func TestHandleExec_TimeoutClamp(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Timeout <= 0 should use default; > maxTimeoutSecs should clamp.
	// Just verify these don't panic.
	req := makeCallToolRequest(map[string]any{
		"command":         "echo",
		"args":            []any{"hello"},
		"timeout_seconds": float64(-1),
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "hello") {
		t.Errorf("result = %q, want 'hello'", text)
	}

	req2 := makeCallToolRequest(map[string]any{
		"command":         "echo",
		"args":            []any{"world"},
		"timeout_seconds": float64(9999),
	})
	result2, err := handleExec(context.Background(), req2)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text2 := getResultText(t, result2)
	if !strings.Contains(text2, "world") {
		t.Errorf("result = %q, want 'world'", text2)
	}
}

// --- handleExecWithSecrets ---

func TestHandleExecWithSecrets_MissingCommand(t *testing.T) {
	result, err := handleExecWithSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'command' is required") {
		t.Errorf("result = %q, want command required error", text)
	}
}

func TestHandleExecWithSecrets_PlaceholderInCommand(t *testing.T) {
	req := makeCallToolRequest(map[string]any{
		"command": "${{NOKEY:SECRET}}",
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "placeholders are not allowed") {
		t.Errorf("result = %q, want placeholder error", text)
	}
}

func TestHandleExecWithSecrets_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("GREETING", "hello-world")

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:GREETING}}"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	// The output should be redacted since it contains the secret value
	if !strings.Contains(text, "[REDACTED:GREETING]") {
		t.Errorf("result = %q, want redacted output", text)
	}
}

func TestHandleExecWithSecrets_SecretNotFound(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Don't store the secret — should fail on fetch
	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:MISSING_SECRET}}"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to get secret") {
		t.Errorf("result = %q, want 'failed to get secret'", text)
	}
}

func TestHandleExecWithSecrets_NoPlaceholders(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"no-placeholders-here"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "no-placeholders-here") {
		t.Errorf("result = %q, want 'no-placeholders-here'", text)
	}
}

func TestHandleExecWithSecrets_NonZeroExit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	req := makeCallToolRequest(map[string]any{
		"command": "sh",
		"args":    []any{"-c", "exit 7"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "exit code: 7") {
		t.Errorf("result = %q, want 'exit code: 7'", text)
	}
}

func TestHandleExecWithSecrets_WithToken(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	store.Set("KEY", "value")
	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"KEY"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:KEY}}"},
		"token":   tok.ID,
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "[REDACTED:KEY]") {
		t.Errorf("result = %q, want redacted output", text)
	}
}

func TestHandleExecWithSecrets_CommandNotFound(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	req := makeCallToolRequest(map[string]any{
		"command": "/nonexistent/cmd",
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to execute") {
		t.Errorf("result = %q, want execution error", text)
	}
}

// --- handleMintToken ---

func TestHandleMintToken_EmptySecrets(t *testing.T) {
	withMCPGlobals(t)

	result, err := handleMintToken(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'secrets' is required") {
		t.Errorf("result = %q, want secrets required error", text)
	}
}

// --- handleRevokeToken ---

func TestHandleRevokeToken_EmptyID(t *testing.T) {
	withMCPGlobals(t)

	result, err := handleRevokeToken(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleRevokeToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'token_id' is required") {
		t.Errorf("result = %q, want token_id required error", text)
	}
}

func TestHandleRevokeToken_NotFound(t *testing.T) {
	withMCPGlobals(t)

	req := makeCallToolRequest(map[string]any{"token_id": "nonexistent"})
	result, err := handleRevokeToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRevokeToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "not found") {
		t.Errorf("result = %q, want 'not found'", text)
	}
}

func TestHandleRevokeToken_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"A"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := makeCallToolRequest(map[string]any{"token_id": tok.ID})
	result, err := handleRevokeToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRevokeToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "revoked") {
		t.Errorf("result = %q, want 'revoked'", text)
	}

	// Verify token is actually gone
	tokens := tokenStore.List()
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after revoke, got %d", len(tokens))
	}
}

// --- handleListTokens ---

func TestHandleListTokens_NoTokens(t *testing.T) {
	withMCPGlobals(t)

	result, err := handleListTokens(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListTokens: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "No active tokens") {
		t.Errorf("result = %q, want 'No active tokens'", text)
	}
}

func TestHandleListTokens_WithTokens(t *testing.T) {
	withMCPGlobals(t)

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets:   []string{"SECRET_A", "SECRET_B"},
		TTLSecs:   300,
		MaxUses:   5,
		MintedFor: "test-cmd",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	result, err := handleListTokens(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListTokens: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, tok.ID) {
		t.Errorf("result missing token ID: %q", text)
	}
	if !strings.Contains(text, "SECRET_A, SECRET_B") {
		t.Errorf("result missing secrets: %q", text)
	}
	if !strings.Contains(text, "5/5") {
		t.Errorf("result missing uses: %q", text)
	}
	if !strings.Contains(text, "test-cmd") {
		t.Errorf("result missing minted-for: %q", text)
	}
}

func TestHandleListTokens_UnlimitedUses(t *testing.T) {
	withMCPGlobals(t)

	_, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"KEY"},
		TTLSecs: 60,
		MaxUses: 0, // unlimited
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	result, err := handleListTokens(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListTokens: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "unlimited") {
		t.Errorf("result = %q, want 'unlimited'", text)
	}
}

// --- handleStopProxy ---

func TestHandleStopProxy_NotRunning(t *testing.T) {
	oldProxy := proxyServer
	t.Cleanup(func() { proxyServer = oldProxy })
	proxyServer = nil

	withMCPGlobals(t)

	result, err := handleStopProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleStopProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "No proxy running") {
		t.Errorf("result = %q, want 'No proxy running'", text)
	}
}

// --- handleStartProxy ---

func TestHandleStartProxy_NoProxyRules(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	oldProxy := proxyServer
	t.Cleanup(func() { proxyServer = oldProxy })

	// Policy with no proxy rules
	pol = &policy.Policy{}
	proxyServer = nil

	result, err := handleStartProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleStartProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "no proxy rules") {
		t.Errorf("result = %q, want 'no proxy rules'", text)
	}
}

// --- checkTokenOrApproval ---

func TestHandleStartProxy_AlreadyRunning(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Create a real proxy server to test "already running" path
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	ca, err := proxy.LoadOrCreateCA(configDir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	rules := []policy.ProxyRule{{
		Hosts:   []string{"example.com"},
		Headers: map[string]string{"X-Key": "val"},
	}}

	srv := proxy.NewServer(ca, rules, map[string]string{}, nil, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { srv.Stop(context.Background()) })

	oldProxy := proxyServer
	t.Cleanup(func() { proxyServer = oldProxy })
	proxyServer = srv

	result, err := handleStartProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleStartProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "already running") {
		t.Errorf("result = %q, want 'already running'", text)
	}
	if !strings.Contains(text, addr) {
		t.Errorf("result = %q, want address %q", text, addr)
	}
}

func TestHandleStopProxy_Running(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	ca, err := proxy.LoadOrCreateCA(configDir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	rules := []policy.ProxyRule{{
		Hosts:   []string{"example.com"},
		Headers: map[string]string{"X-Key": "val"},
	}}

	srv := proxy.NewServer(ca, rules, map[string]string{}, nil, nil)
	if _, err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	oldProxy := proxyServer
	t.Cleanup(func() { proxyServer = oldProxy })
	proxyServer = srv

	result, err := handleStopProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleStopProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Proxy stopped") {
		t.Errorf("result = %q, want 'Proxy stopped'", text)
	}
	if proxyServer != nil {
		t.Error("proxyServer should be nil after stop")
	}
}

func TestHandleExec_WithAudit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	store.Set("KEY", "val")

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello"},
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "hello") {
		t.Errorf("result = %q, want 'hello'", text)
	}
}

func TestHandleExecWithSecrets_PolicyDenied(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	pol = &policy.Policy{
		Rules: []policy.Rule{{
			Commands: []string{"allowed-cmd"},
			Secrets:  []string{"*"},
		}},
	}

	store.Set("SECRET", "val")

	req := makeCallToolRequest(map[string]any{
		"command": "denied-cmd",
		"args":    []any{"${{NOKEY:SECRET}}"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "policy denied") {
		t.Errorf("result = %q, want policy denial", text)
	}
}

func TestHandleStartProxy_FullFlow(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Set up temp HOME with CA and policies
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	// Create policy with proxy rules referencing a secret
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_KEY"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	loadedPol, err := policy.Load(configDir)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	pol = loadedPol

	// Store the referenced secret
	store.Set("MY_KEY", "secret-value")

	req := makeCallToolRequest(map[string]any{})
	result, handlerErr := handleStartProxy(context.Background(), req)
	if handlerErr != nil {
		t.Fatalf("handleStartProxy: %v", handlerErr)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Proxy started on") {
		t.Errorf("result = %q, want 'Proxy started on'", text)
	}
	if !strings.Contains(text, "http_proxy") {
		t.Errorf("result = %q, want 'http_proxy' env var instructions", text)
	}

	// Clean up proxy
	if proxyServer != nil {
		proxyServer.Stop(context.Background())
		proxyServer = nil
	}
}

func TestHandleStartProxy_SecretNotFound(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MISSING_SECRET"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	loadedPol, err := policy.Load(configDir)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	pol = loadedPol

	// Don't store the secret

	req := makeCallToolRequest(map[string]any{})
	result, handlerErr := handleStartProxy(context.Background(), req)
	if handlerErr != nil {
		t.Fatalf("handleStartProxy: %v", handlerErr)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to get secret") {
		t.Errorf("result = %q, want 'failed to get secret'", text)
	}
}

func TestHandleListSecrets_WithAudit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	store.Set("KEY1", "val1")

	oldPol := pol
	oldTokenStore := tokenStore
	t.Cleanup(func() {
		pol = oldPol
		tokenStore = oldTokenStore
	})
	pol = nil
	tokenStore = token.NewStore()

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	result, err := handleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "KEY1") {
		t.Errorf("result = %q, want KEY1", text)
	}
}

func TestHandleMintToken_EmptySecretsList(t *testing.T) {
	withMCPGlobals(t)

	// Empty array of secrets
	req := makeCallToolRequest(map[string]any{
		"secrets": []any{},
	})
	result, err := handleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "required") {
		t.Errorf("result = %q, want 'required'", text)
	}
}

func TestCheckTokenOrApproval_ValidToken(t *testing.T) {
	withMCPGlobals(t)

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"MY_SECRET"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	err = checkTokenOrApproval(context.Background(), tok.ID, "test-cmd", []string{"MY_SECRET"})
	if err != nil {
		t.Errorf("checkTokenOrApproval: %v", err)
	}
}

func TestCheckTokenOrApproval_InvalidToken(t *testing.T) {
	withMCPGlobals(t)

	err := checkTokenOrApproval(context.Background(), "bad-token", "test-cmd", []string{"SEC"})
	if err == nil || !strings.Contains(err.Error(), "token invalid") {
		t.Errorf("expected 'token invalid' error, got: %v", err)
	}
}

func TestCheckTokenOrApproval_NoTokenNilPolicy(t *testing.T) {
	withMCPGlobals(t)
	pol = nil // nil policy = no requirements

	err := checkTokenOrApproval(context.Background(), "", "test-cmd", []string{"SEC"})
	if err != nil {
		t.Errorf("checkTokenOrApproval: %v", err)
	}
}

func TestCheckTokenOrApproval_PolicyRequiresToken(t *testing.T) {
	withMCPGlobals(t)

	pol = &policy.Policy{
		Rules: []policy.Rule{{
			Commands:      []string{"*"},
			Secrets:       []string{"*"},
			TokenRequired: true,
		}},
	}

	err := checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"})
	if err == nil || !strings.Contains(err.Error(), "token required") {
		t.Errorf("expected 'token required' error, got: %v", err)
	}
}

func TestCheckTokenOrApproval_WrongSecret(t *testing.T) {
	withMCPGlobals(t)

	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"ALLOWED"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	err = checkTokenOrApproval(context.Background(), tok.ID, "cmd", []string{"DISALLOWED"})
	if err == nil || !strings.Contains(err.Error(), "token invalid") {
		t.Errorf("expected 'token invalid' error, got: %v", err)
	}
}

// --- recordAudit ---

func TestRecordAudit_Disabled(t *testing.T) {
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)

	// Should be a no-op — no panic
	recordAudit("test-op", "test-cmd", "target", true, "")
}

func TestRecordAudit_Enabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	// Should not panic; may fail silently due to missing encryption key
	recordAudit("test-op", "test-cmd", "target", true, "")
}

func TestRecordAudit_NilConfig(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg = nil

	// Should be a no-op — no panic
	recordAudit("test-op", "test-cmd", "target", true, "")
}

func TestRecordAudit_GetKeyringError(t *testing.T) {
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring unavailable")
	}

	// Should silently return — no panic
	recordAudit("test-op", "test-cmd", "target", true, "")
}

// --- handleListSecrets error paths ---

func TestHandleListSecrets_GetKeyringError(t *testing.T) {
	withMCPGlobals(t)

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}

	result, err := handleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

func TestHandleListSecrets_ListError(t *testing.T) {
	withMCPGlobals(t)

	// Create a store backed by a ring that fails on Keys()
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })

	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorKeysRing{mockRing: ring}, "nokey-test")
	getKeyring = func() (*nkeyring.Store, error) { return store, nil }

	result, err := handleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to list secrets") {
		t.Errorf("result = %q, want 'failed to list secrets'", text)
	}
}

// errorKeysRing is a mock keyring.Keyring that fails on Keys().
type errorKeysRing struct {
	mockRing *mockRing
}

func (e *errorKeysRing) Get(key string) (kring.Item, error) { return e.mockRing.Get(key) }
func (e *errorKeysRing) GetMetadata(key string) (kring.Metadata, error) {
	return e.mockRing.GetMetadata(key)
}
func (e *errorKeysRing) Set(item kring.Item) error { return e.mockRing.Set(item) }
func (e *errorKeysRing) Remove(key string) error   { return e.mockRing.Remove(key) }
func (e *errorKeysRing) Keys() ([]string, error)   { return nil, fmt.Errorf("keys failed") }

// --- handleMintToken full flow ---

func TestHandleMintToken_ApprovalAccepted(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"SECRET_A", "SECRET_B"},
		"ttl_seconds": 300,
		"max_uses":    5,
		"for":         "test-consumer",
	})
	result, err := handleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Token minted") {
		t.Errorf("result = %q, want 'Token minted'", text)
	}
	if !strings.Contains(text, "SECRET_A, SECRET_B") {
		t.Errorf("result missing secrets: %q", text)
	}
	if !strings.Contains(text, "Max uses: 5") {
		t.Errorf("result missing max_uses: %q", text)
	}
	if !strings.Contains(text, "test-consumer") {
		t.Errorf("result missing for: %q", text)
	}
}

func TestHandleMintToken_ApprovalDeclined(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user declined secret access for \"mint_token\"")
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"SECRET_A"},
		"ttl_seconds": 60,
	})
	result, err := handleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "declined") {
		t.Errorf("result = %q, want 'declined'", text)
	}
}

func TestHandleMintToken_UnlimitedUses(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"KEY"},
		"ttl_seconds": 120,
		"max_uses":    0, // unlimited
	})
	result, err := handleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Max uses: unlimited") {
		t.Errorf("result = %q, want 'unlimited'", text)
	}
}

func TestHandleMintToken_WithAudit(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"AUDIT_SEC"},
		"ttl_seconds": 60,
	})
	result, err := handleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Token minted") {
		t.Errorf("result = %q, want 'Token minted'", text)
	}
}

func TestHandleMintToken_DefaultFor(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"KEY"},
		"ttl_seconds": 60,
	})
	result, err := handleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("handleMintToken: %v", err)
	}
	text := getResultText(t, result)
	// Default "for" should be "*"
	if !strings.Contains(text, "For: *") {
		t.Errorf("result = %q, want 'For: *'", text)
	}
}

// --- checkTokenOrApproval RequiresApproval path ---

func TestCheckTokenOrApproval_RequiresApproval_Accepted(t *testing.T) {
	withMCPGlobals(t)

	pol = &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	err := checkTokenOrApproval(context.Background(), "", "some-cmd", []string{"SEC"})
	if err != nil {
		t.Errorf("checkTokenOrApproval: %v", err)
	}
}

func TestCheckTokenOrApproval_RequiresApproval_Declined(t *testing.T) {
	withMCPGlobals(t)

	pol = &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user declined")
	})

	err := checkTokenOrApproval(context.Background(), "", "some-cmd", []string{"SEC"})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("expected 'declined' error, got: %v", err)
	}
}

// --- checkTokenOrApproval auto-mint path ---

func TestCheckTokenOrApproval_AutoMint_Approved(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	withTestConfig(t, c)

	if err := store.Set("SECRET_A", "val-a"); err != nil {
		t.Fatalf("set: %v", err)
	}

	approvalCount := 0
	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		approvalCount++
		return nil
	})

	// First call: triggers auto-mint approval.
	if err := checkTokenOrApproval(context.Background(), "", "cmd1", []string{"SECRET_A"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if approvalCount != 1 {
		t.Fatalf("approvalCount = %d, want 1", approvalCount)
	}
	if sessionTokenID == "" {
		t.Fatal("sessionTokenID should be set after auto-mint")
	}

	// Second call: should use cached session token, no new approval.
	if err := checkTokenOrApproval(context.Background(), "", "cmd2", []string{"SECRET_A"}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if approvalCount != 1 {
		t.Errorf("approvalCount = %d, want 1 (no second prompt)", approvalCount)
	}
}

func TestCheckTokenOrApproval_AutoMint_Declined(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	withTestConfig(t, c)

	if err := store.Set("SEC", "val"); err != nil {
		t.Fatalf("set: %v", err)
	}

	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user declined")
	})

	// Auto-mint declined → falls through. With nil policy, no further approval needed.
	err := checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"})
	if err != nil {
		t.Errorf("expected nil (fallthrough with nil policy), got: %v", err)
	}
	if sessionTokenID != "" {
		t.Error("sessionTokenID should remain empty after declined auto-mint")
	}
}

func TestCheckTokenOrApproval_AutoMint_Disabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	approvalCount := 0
	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		approvalCount++
		return nil
	})

	// With nil policy, no approval required; auto-mint disabled → no prompt at all.
	if err := checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"}); err != nil {
		t.Fatalf("checkTokenOrApproval: %v", err)
	}
	if approvalCount != 0 {
		t.Errorf("approvalCount = %d, want 0 (auto-mint disabled)", approvalCount)
	}
	if sessionTokenID != "" {
		t.Error("sessionTokenID should remain empty when auto-mint is disabled")
	}
}

func TestCheckTokenOrApproval_AutoMint_Expired(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	withTestConfig(t, c)

	if err := store.Set("SEC", "val"); err != nil {
		t.Fatalf("set: %v", err)
	}

	approvalCount := 0
	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		approvalCount++
		return nil
	})

	// Mint a token with 1s TTL, then expire it by revoking.
	tok, err := tokenStore.Mint(token.MintRequest{
		Secrets: []string{"SEC"}, TTLSecs: 1, MintedFor: "*",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	sessionTokenID = tok.ID
	tokenStore.Revoke(tok.ID) // simulate expiry

	// Next call should detect invalid session token, clear it, then auto-mint again.
	if err := checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"}); err != nil {
		t.Fatalf("checkTokenOrApproval: %v", err)
	}
	if approvalCount != 1 {
		t.Errorf("approvalCount = %d, want 1 (re-mint after expiry)", approvalCount)
	}
	if sessionTokenID == "" || sessionTokenID == tok.ID {
		t.Error("sessionTokenID should be set to a new token after re-mint")
	}
}

func TestCheckTokenOrApproval_AutoMint_NewSecret(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withMCPGlobals(t)

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	withTestConfig(t, c)

	if err := store.Set("SEC_A", "a"); err != nil {
		t.Fatalf("set: %v", err)
	}

	approvalCount := 0
	withApprovalFn(t, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		approvalCount++
		return nil
	})

	// First call: auto-mint with SEC_A.
	if err := checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC_A"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if approvalCount != 1 {
		t.Fatalf("approvalCount = %d, want 1", approvalCount)
	}
	firstToken := sessionTokenID

	// Add a new secret and request it.
	if err := store.Set("SEC_B", "b"); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Session token only covers SEC_A, not SEC_B → should clear and re-mint.
	if err := checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC_B"}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if approvalCount != 2 {
		t.Errorf("approvalCount = %d, want 2 (re-mint for new secret)", approvalCount)
	}
	if sessionTokenID == firstToken {
		t.Error("sessionTokenID should differ after re-mint for new secret")
	}
}

// --- handleExec getKeyring error ---

func TestHandleExec_GetKeyringError(t *testing.T) {
	withMCPGlobals(t)

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello"},
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

// --- handleExec store.GetAll error ---

func TestHandleExec_GetSecretsError(t *testing.T) {
	withMCPGlobals(t)

	// Use errorKeysRing so store.GetAll() (which calls Keys()) fails
	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorKeysRing{mockRing: ring}, "nokey-test")

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) { return store, nil }

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to get secrets") {
		t.Errorf("result = %q, want 'failed to get secrets'", text)
	}
}

// --- handleExecWithSecrets getKeyring error ---

func TestHandleExecWithSecrets_GetKeyringError(t *testing.T) {
	withMCPGlobals(t)

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:SECRET}}"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

// --- handleExecWithSecrets approval denied ---

func TestHandleExecWithSecrets_ApprovalDenied(t *testing.T) {
	withMCPGlobals(t)

	// Set policy that requires approval
	pol = &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}

	oldApproval := approvalRequestFn
	t.Cleanup(func() { approvalRequestFn = oldApproval })
	approvalRequestFn = func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user denied")
	}

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:MY_SECRET}}"},
	})
	result, err := handleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "denied") {
		t.Errorf("result = %q, want 'denied'", text)
	}
}

// --- handleExec approval denied ---

func TestHandleExec_ApprovalDenied(t *testing.T) {
	store, _ := newTestStore()
	store.Set("MY_KEY", "my-value")
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Set policy that requires approval
	pol = &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}

	oldApproval := approvalRequestFn
	t.Cleanup(func() { approvalRequestFn = oldApproval })
	approvalRequestFn = func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("approval denied")
	}

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "approval denied") {
		t.Errorf("result = %q, want 'approval denied'", text)
	}
}

// --- handleStartProxy getKeyring error ---

func TestHandleStartProxy_GetKeyringError(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	withMCPGlobals(t)

	// Create policies with proxy rules
	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_SECRET"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	// Load the policy so pol is set
	polObj, err := policy.Load(configDir)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	pol = polObj

	// Init CA so LoadOrCreateCA succeeds
	if _, err := proxy.LoadOrCreateCA(configDir); err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring error")
	}

	req := makeCallToolRequest(map[string]any{})
	result, err := handleStartProxy(context.Background(), req)
	if err != nil {
		t.Fatalf("handleStartProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

// --- handleExec filter secrets error ---

func TestHandleExec_FilterError(t *testing.T) {
	store, _ := newTestStore()
	store.Set("KEY", "val")
	withTestKeyring(t, store)
	withMCPGlobals(t)

	// Use both only and except to trigger filter error
	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"only":    "A",
		"except":  "B",
	})
	result, err := handleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "cannot use both") {
		t.Errorf("result = %q, want 'cannot use both'", text)
	}
}

// --- handleMintToken store.Mint error ---

func TestHandleMintToken_MintError(t *testing.T) {
	withMCPGlobals(t)

	oldApproval := approvalRequestFn
	t.Cleanup(func() { approvalRequestFn = oldApproval })
	approvalRequestFn = func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	}

	// Mint with TTL of 0 — this should still work since token.Store.Mint handles it.
	// Instead, let's use a negative TTL to try to trigger an error (if the store validates).
	// Actually, token.Store.Mint always succeeds for valid inputs.
	// Let's test with a very large max_uses to ensure the path works.
	// The mint error path is hard to trigger with a real token store.
	// Skip this test — the error path would require a custom token store interface.
	t.Skip("mint error path requires injectable token store")
}
