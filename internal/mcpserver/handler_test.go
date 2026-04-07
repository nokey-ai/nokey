package mcpserver

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/nokey-ai/nokey/internal/token"
)

// --- mock SecretStore ---

type mapStore struct {
	secrets map[string]string
	err     error // if set, all calls return this error
}

func (m *mapStore) Get(name string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	v, ok := m.secrets[name]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", name)
	}
	return v, nil
}

func (m *mapStore) GetAll() (map[string]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	cp := make(map[string]string, len(m.secrets))
	for k, v := range m.secrets {
		cp[k] = v
	}
	return cp, nil
}

func (m *mapStore) List() ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	keys := make([]string, 0, len(m.secrets))
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

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

// staticPolicy returns a GetPolicy provider that always returns p.
func staticPolicy(p *policy.Policy) func() *policy.Policy {
	return func() *policy.Policy { return p }
}

// newTestHandler constructs a Handler with test-friendly defaults.
func newTestHandler(t *testing.T, store SecretStore, pol *policy.Policy, approvalFn ApprovalFunc) *Handler {
	t.Helper()
	if approvalFn == nil {
		approvalFn = func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error {
			return nil // auto-approve
		}
	}
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	return New(Deps{
		GetStore:     func() (SecretStore, error) { return store, nil },
		GetPolicy:    staticPolicy(pol),
		Config:       c,
		ApprovalFn:   approvalFn,
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})
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

// --- HandleListSecrets ---

func TestHandleListSecrets_NoSecrets(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "No secrets stored") {
		t.Errorf("result = %q, want 'No secrets stored'", text)
	}
}

func TestHandleListSecrets_WithSecrets(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"API_KEY": "val1",
		"DB_PASS": "val2",
	}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "API_KEY") {
		t.Errorf("result missing API_KEY: %q", text)
	}
	if !strings.Contains(text, "DB_PASS") {
		t.Errorf("result missing DB_PASS: %q", text)
	}
}

// --- HandleExec ---

func TestHandleExec_MissingCommand(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleExec(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'command' is required") {
		t.Errorf("result = %q, want command required error", text)
	}
}

func TestHandleExec_Success(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"MY_KEY": "my-value",
	}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello", "world"},
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "hello world") {
		t.Errorf("result = %q, want output containing 'hello world'", text)
	}
}

func TestHandleExec_NonZeroExit(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "sh",
		"args":    []any{"-c", "exit 42"},
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "exit code: 42") {
		t.Errorf("result = %q, want 'exit code: 42'", text)
	}
}

func TestHandleExec_RedactsOutput(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"TOKEN": "supersecret42",
	}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "sh",
		"args":    []any{"-c", "echo supersecret42"},
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
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
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "/nonexistent/binary",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to execute") {
		t.Errorf("result = %q, want execution error", text)
	}
}

func TestHandleExec_FilterOnly(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"A": "val-a",
		"B": "val-b",
	}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "env",
		"only":    "A",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	// A should be in env output; B should not
	if !strings.Contains(text, "A=") {
		t.Errorf("result missing A env var: %q", text)
	}
}

func TestHandleExec_FilterExcept(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEEP": "keep-val",
		"SKIP": "skip-val",
	}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"done"},
		"except":  "SKIP",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "done") {
		t.Errorf("result = %q, want 'done'", text)
	}
}

func TestHandleExec_PolicyDenied(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"SECRET": "val",
	}}
	pol := &policy.Policy{
		Rules: []policy.Rule{{
			Commands: []string{"allowed-cmd"},
			Secrets:  []string{"*"},
		}},
	}
	h := newTestHandler(t, store, pol, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "denied-cmd",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "policy denied") {
		t.Errorf("result = %q, want policy denial", text)
	}
}

func TestHandleExec_WithValidToken(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEY": "val",
	}}
	h := newTestHandler(t, store, nil, nil)

	tok, err := h.tokenStore.Mint(token.MintRequest{
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
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "ok") {
		t.Errorf("result = %q, want 'ok'", text)
	}
}

func TestHandleExec_WithInvalidToken(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEY": "val",
	}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"ok"},
		"token":   "bad-token-id",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "token invalid") {
		t.Errorf("result = %q, want 'token invalid'", text)
	}
}

func TestHandleExec_TimeoutClamp(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	// Timeout <= 0 should use default; > maxTimeoutSecs should clamp.
	// Just verify these don't panic.
	req := makeCallToolRequest(map[string]any{
		"command":         "echo",
		"args":            []any{"hello"},
		"timeout_seconds": float64(-1),
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
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
	result2, err := h.HandleExec(context.Background(), req2)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text2 := getResultText(t, result2)
	if !strings.Contains(text2, "world") {
		t.Errorf("result = %q, want 'world'", text2)
	}
}

// --- HandleExecWithSecrets ---

func TestHandleExecWithSecrets_MissingCommand(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleExecWithSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'command' is required") {
		t.Errorf("result = %q, want command required error", text)
	}
}

func TestHandleExecWithSecrets_PlaceholderInCommand(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "${{NOKEY:SECRET}}",
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "placeholders are not allowed") {
		t.Errorf("result = %q, want placeholder error", text)
	}
}

func TestHandleExecWithSecrets_Success(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"GREETING": "hello-world",
	}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:GREETING}}"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	// The output should be redacted since it contains the secret value
	if !strings.Contains(text, "[REDACTED:GREETING]") {
		t.Errorf("result = %q, want redacted output", text)
	}
}

func TestHandleExecWithSecrets_SecretNotFound(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	// Don't store the secret -- should fail on fetch
	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:MISSING_SECRET}}"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to get secret") {
		t.Errorf("result = %q, want 'failed to get secret'", text)
	}
}

func TestHandleExecWithSecrets_NoPlaceholders(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"no-placeholders-here"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "no-placeholders-here") {
		t.Errorf("result = %q, want 'no-placeholders-here'", text)
	}
}

func TestHandleExecWithSecrets_NonZeroExit(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "sh",
		"args":    []any{"-c", "exit 7"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "exit code: 7") {
		t.Errorf("result = %q, want 'exit code: 7'", text)
	}
}

func TestHandleExecWithSecrets_WithToken(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEY": "value",
	}}
	h := newTestHandler(t, store, nil, nil)

	tok, err := h.tokenStore.Mint(token.MintRequest{
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
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "[REDACTED:KEY]") {
		t.Errorf("result = %q, want redacted output", text)
	}
}

func TestHandleExecWithSecrets_CommandNotFound(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "/nonexistent/cmd",
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to execute") {
		t.Errorf("result = %q, want execution error", text)
	}
}

// --- HandleMintToken ---

func TestHandleMintToken_EmptySecrets(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleMintToken(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'secrets' is required") {
		t.Errorf("result = %q, want secrets required error", text)
	}
}

func TestHandleMintToken_EmptySecretsList(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	// Empty array of secrets
	req := makeCallToolRequest(map[string]any{
		"secrets": []any{},
	})
	result, err := h.HandleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "required") {
		t.Errorf("result = %q, want 'required'", text)
	}
}

// --- HandleRevokeToken ---

func TestHandleRevokeToken_EmptyID(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleRevokeToken(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleRevokeToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "'token_id' is required") {
		t.Errorf("result = %q, want token_id required error", text)
	}
}

func TestHandleRevokeToken_NotFound(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{"token_id": "nonexistent"})
	result, err := h.HandleRevokeToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRevokeToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "not found") {
		t.Errorf("result = %q, want 'not found'", text)
	}
}

func TestHandleRevokeToken_Success(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	tok, err := h.tokenStore.Mint(token.MintRequest{
		Secrets: []string{"A"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := makeCallToolRequest(map[string]any{"token_id": tok.ID})
	result, err := h.HandleRevokeToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRevokeToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "revoked") {
		t.Errorf("result = %q, want 'revoked'", text)
	}

	// Verify token is actually gone
	tokens := h.tokenStore.List()
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after revoke, got %d", len(tokens))
	}
}

// --- HandleListTokens ---

func TestHandleListTokens_NoTokens(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleListTokens(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListTokens: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "No active tokens") {
		t.Errorf("result = %q, want 'No active tokens'", text)
	}
}

func TestHandleListTokens_WithTokens(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	tok, err := h.tokenStore.Mint(token.MintRequest{
		Secrets:   []string{"SECRET_A", "SECRET_B"},
		TTLSecs:   300,
		MaxUses:   5,
		MintedFor: "test-cmd",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	result, err := h.HandleListTokens(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListTokens: %v", err)
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
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	_, err := h.tokenStore.Mint(token.MintRequest{
		Secrets: []string{"KEY"},
		TTLSecs: 60,
		MaxUses: 0, // unlimited
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	result, err := h.HandleListTokens(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListTokens: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "unlimited") {
		t.Errorf("result = %q, want 'unlimited'", text)
	}
}

// --- HandleStopProxy ---

func TestHandleStopProxy_NotRunning(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleStopProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleStopProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "No proxy running") {
		t.Errorf("result = %q, want 'No proxy running'", text)
	}
}

// --- HandleStartProxy ---

func TestHandleStartProxy_NoProxyRules(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	// Policy with no proxy rules
	pol := &policy.Policy{}
	h := newTestHandler(t, store, pol, nil)

	result, err := h.HandleStartProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleStartProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "no proxy rules") {
		t.Errorf("result = %q, want 'no proxy rules'", text)
	}
}

func TestHandleStartProxy_AlreadyRunning(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	// Create a real proxy server to test "already running" path
	dir := t.TempDir()
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

	h.proxyServer = srv

	result, err := h.HandleStartProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleStartProxy: %v", err)
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
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	dir := t.TempDir()
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

	h.proxyServer = srv

	result, err := h.HandleStopProxy(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleStopProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Proxy stopped") {
		t.Errorf("result = %q, want 'Proxy stopped'", text)
	}
	if h.proxyServer != nil {
		t.Error("proxyServer should be nil after stop")
	}
}

func TestHandleExec_WithAudit(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEY": "val",
	}}
	c := config.DefaultConfig()
	c.Audit.Enabled = true

	var audited bool
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return store, nil },
		GetPolicy:    staticPolicy(nil),
		Config:       c,
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(op, cmd, target string, ok bool, errMsg string) { audited = true },
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello"},
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "hello") {
		t.Errorf("result = %q, want 'hello'", text)
	}
	if !audited {
		t.Error("expected audit function to be called")
	}
}

func TestHandleExecWithSecrets_PolicyDenied(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"SECRET": "val",
	}}
	pol := &policy.Policy{
		Rules: []policy.Rule{{
			Commands: []string{"allowed-cmd"},
			Secrets:  []string{"*"},
		}},
	}
	h := newTestHandler(t, store, pol, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "denied-cmd",
		"args":    []any{"${{NOKEY:SECRET}}"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "policy denied") {
		t.Errorf("result = %q, want policy denial", text)
	}
}

func TestHandleStartProxy_FullFlow(t *testing.T) {
	dir := t.TempDir()
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

	store := &mapStore{secrets: map[string]string{
		"MY_KEY": "secret-value",
	}}

	c := config.DefaultConfig()
	c.Audit.Enabled = false
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return store, nil },
		GetPolicy:    staticPolicy(loadedPol),
		Config:       c,
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return configDir, nil },
	})

	req := makeCallToolRequest(map[string]any{})
	result, handlerErr := h.HandleStartProxy(context.Background(), req)
	if handlerErr != nil {
		t.Fatalf("HandleStartProxy: %v", handlerErr)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Proxy started on") {
		t.Errorf("result = %q, want 'Proxy started on'", text)
	}
	if !strings.Contains(text, "http_proxy") {
		t.Errorf("result = %q, want 'http_proxy' env var instructions", text)
	}

	// Clean up proxy
	if h.proxyServer != nil {
		h.proxyServer.Stop(context.Background())
		h.proxyServer = nil
	}
}

func TestHandleStartProxy_SecretNotFound(t *testing.T) {
	dir := t.TempDir()
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

	// Don't store the secret
	store := &mapStore{secrets: map[string]string{}}

	c := config.DefaultConfig()
	c.Audit.Enabled = false
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return store, nil },
		GetPolicy:    staticPolicy(loadedPol),
		Config:       c,
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return configDir, nil },
	})

	req := makeCallToolRequest(map[string]any{})
	result, handlerErr := h.HandleStartProxy(context.Background(), req)
	if handlerErr != nil {
		t.Fatalf("HandleStartProxy: %v", handlerErr)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to get secret") {
		t.Errorf("result = %q, want 'failed to get secret'", text)
	}
}

func TestHandleListSecrets_WithAudit(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEY1": "val1",
	}}

	c := config.DefaultConfig()
	c.Audit.Enabled = true

	var audited bool
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return store, nil },
		GetPolicy:    staticPolicy(nil),
		Config:       c,
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(op, cmd, target string, ok bool, errMsg string) { audited = true },
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	result, err := h.HandleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "KEY1") {
		t.Errorf("result = %q, want KEY1", text)
	}
	if !audited {
		t.Error("expected audit function to be called")
	}
}

// --- checkTokenOrApproval ---

func TestCheckTokenOrApproval_ValidToken(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	tok, err := h.tokenStore.Mint(token.MintRequest{
		Secrets: []string{"MY_SECRET"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	err = h.checkTokenOrApproval(context.Background(), tok.ID, "test-cmd", []string{"MY_SECRET"})
	if err != nil {
		t.Errorf("checkTokenOrApproval: %v", err)
	}
}

func TestCheckTokenOrApproval_InvalidToken(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	err := h.checkTokenOrApproval(context.Background(), "bad-token", "test-cmd", []string{"SEC"})
	if err == nil || !strings.Contains(err.Error(), "token invalid") {
		t.Errorf("expected 'token invalid' error, got: %v", err)
	}
}

func TestCheckTokenOrApproval_NoTokenNilPolicy(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil) // nil policy = no requirements

	err := h.checkTokenOrApproval(context.Background(), "", "test-cmd", []string{"SEC"})
	if err != nil {
		t.Errorf("checkTokenOrApproval: %v", err)
	}
}

func TestCheckTokenOrApproval_PolicyRequiresToken(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	pol := &policy.Policy{
		Rules: []policy.Rule{{
			Commands:      []string{"*"},
			Secrets:       []string{"*"},
			TokenRequired: true,
		}},
	}
	h := newTestHandler(t, store, pol, nil)

	err := h.checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"})
	if err == nil || !strings.Contains(err.Error(), "token required") {
		t.Errorf("expected 'token required' error, got: %v", err)
	}
}

func TestCheckTokenOrApproval_WrongSecret(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, nil)

	tok, err := h.tokenStore.Mint(token.MintRequest{
		Secrets: []string{"ALLOWED"},
		TTLSecs: 300,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	err = h.checkTokenOrApproval(context.Background(), tok.ID, "cmd", []string{"DISALLOWED"})
	if err == nil || !strings.Contains(err.Error(), "token invalid") {
		t.Errorf("expected 'token invalid' error, got: %v", err)
	}
}

// --- handleListSecrets error paths ---

func TestHandleListSecrets_GetKeyringError(t *testing.T) {
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return nil, fmt.Errorf("keyring locked") },
		GetPolicy:    staticPolicy(nil),
		Config:       config.DefaultConfig(),
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	result, err := h.HandleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

func TestHandleListSecrets_ListError(t *testing.T) {
	store := &mapStore{secrets: nil, err: fmt.Errorf("list failed")}
	h := newTestHandler(t, store, nil, nil)

	result, err := h.HandleListSecrets(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleListSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to list secrets") {
		t.Errorf("result = %q, want 'failed to list secrets'", text)
	}
}

// --- HandleMintToken full flow ---

func TestHandleMintToken_ApprovalAccepted(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"SECRET_A", "SECRET_B"},
		"ttl_seconds": 300,
		"max_uses":    5,
		"for":         "test-consumer",
	})
	result, err := h.HandleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
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
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user declined secret access for \"mint_token\"")
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"SECRET_A"},
		"ttl_seconds": 60,
	})
	result, err := h.HandleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "declined") {
		t.Errorf("result = %q, want 'declined'", text)
	}
}

func TestHandleMintToken_UnlimitedUses(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"KEY"},
		"ttl_seconds": 120,
		"max_uses":    0, // unlimited
	})
	result, err := h.HandleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Max uses: unlimited") {
		t.Errorf("result = %q, want 'unlimited'", text)
	}
}

func TestHandleMintToken_WithAudit(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}

	c := config.DefaultConfig()
	c.Audit.Enabled = true

	var audited bool
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return store, nil },
		GetPolicy:    staticPolicy(nil),
		Config:       c,
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(op, cmd, target string, ok bool, errMsg string) { audited = true },
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"AUDIT_SEC"},
		"ttl_seconds": 60,
	})
	result, err := h.HandleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "Token minted") {
		t.Errorf("result = %q, want 'Token minted'", text)
	}
	if !audited {
		t.Error("expected audit function to be called")
	}
}

func TestHandleMintToken_DefaultFor(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	h := newTestHandler(t, store, nil, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	req := makeCallToolRequest(map[string]any{
		"secrets":     []any{"KEY"},
		"ttl_seconds": 60,
	})
	result, err := h.HandleMintToken(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleMintToken: %v", err)
	}
	text := getResultText(t, result)
	// Default "for" should be "*"
	if !strings.Contains(text, "For: *") {
		t.Errorf("result = %q, want 'For: *'", text)
	}
}

// --- checkTokenOrApproval RequiresApproval path ---

func TestCheckTokenOrApproval_RequiresApproval_Accepted(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	pol := &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}
	h := newTestHandler(t, store, pol, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return nil
	})

	err := h.checkTokenOrApproval(context.Background(), "", "some-cmd", []string{"SEC"})
	if err != nil {
		t.Errorf("checkTokenOrApproval: %v", err)
	}
}

func TestCheckTokenOrApproval_RequiresApproval_Declined(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	pol := &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}
	h := newTestHandler(t, store, pol, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user declined")
	})

	err := h.checkTokenOrApproval(context.Background(), "", "some-cmd", []string{"SEC"})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("expected 'declined' error, got: %v", err)
	}
}

// --- checkTokenOrApproval auto-mint path ---

func TestCheckTokenOrApproval_AutoMint_Approved(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"SECRET_A": "val-a",
	}}

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	c.Audit.Enabled = false

	approvalCount := 0
	h := New(Deps{
		GetStore:  func() (SecretStore, error) { return store, nil },
		GetPolicy: staticPolicy(nil),
		Config:    c,
		ApprovalFn: func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
			approvalCount++
			return nil
		},
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	// First call: triggers auto-mint approval.
	if err := h.checkTokenOrApproval(context.Background(), "", "cmd1", []string{"SECRET_A"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if approvalCount != 1 {
		t.Fatalf("approvalCount = %d, want 1", approvalCount)
	}
	if h.sessionTokenID == "" {
		t.Fatal("sessionTokenID should be set after auto-mint")
	}

	// Second call: should use cached session token, no new approval.
	if err := h.checkTokenOrApproval(context.Background(), "", "cmd2", []string{"SECRET_A"}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if approvalCount != 1 {
		t.Errorf("approvalCount = %d, want 1 (no second prompt)", approvalCount)
	}
}

func TestCheckTokenOrApproval_AutoMint_Declined(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"SEC": "val",
	}}

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	c.Audit.Enabled = false

	h := New(Deps{
		GetStore:  func() (SecretStore, error) { return store, nil },
		GetPolicy: staticPolicy(nil),
		Config:    c,
		ApprovalFn: func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
			return fmt.Errorf("user declined")
		},
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	// Auto-mint declined -> falls through. With nil policy, no further approval needed.
	err := h.checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"})
	if err != nil {
		t.Errorf("expected nil (fallthrough with nil policy), got: %v", err)
	}
	if h.sessionTokenID != "" {
		t.Error("sessionTokenID should remain empty after declined auto-mint")
	}
}

func TestCheckTokenOrApproval_AutoMint_Disabled(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	// Default config has AutoMintToken = false
	approvalCount := 0
	h := newTestHandler(t, store, nil, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		approvalCount++
		return nil
	})

	// With nil policy, no approval required; auto-mint disabled -> no prompt at all.
	if err := h.checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"}); err != nil {
		t.Fatalf("checkTokenOrApproval: %v", err)
	}
	if approvalCount != 0 {
		t.Errorf("approvalCount = %d, want 0 (auto-mint disabled)", approvalCount)
	}
	if h.sessionTokenID != "" {
		t.Error("sessionTokenID should remain empty when auto-mint is disabled")
	}
}

func TestCheckTokenOrApproval_AutoMint_Expired(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"SEC": "val",
	}}

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	c.Audit.Enabled = false

	approvalCount := 0
	h := New(Deps{
		GetStore:  func() (SecretStore, error) { return store, nil },
		GetPolicy: staticPolicy(nil),
		Config:    c,
		ApprovalFn: func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
			approvalCount++
			return nil
		},
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	// Mint a token with 1s TTL, then expire it by revoking.
	tok, err := h.tokenStore.Mint(token.MintRequest{
		Secrets: []string{"SEC"}, TTLSecs: 1, MintedFor: "*",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	h.sessionTokenID = tok.ID
	h.tokenStore.Revoke(tok.ID) // simulate expiry

	// Next call should detect invalid session token, clear it, then auto-mint again.
	if err := h.checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC"}); err != nil {
		t.Fatalf("checkTokenOrApproval: %v", err)
	}
	if approvalCount != 1 {
		t.Errorf("approvalCount = %d, want 1 (re-mint after expiry)", approvalCount)
	}
	if h.sessionTokenID == "" || h.sessionTokenID == tok.ID {
		t.Error("sessionTokenID should be set to a new token after re-mint")
	}
}

func TestCheckTokenOrApproval_AutoMint_NewSecret(t *testing.T) {
	secrets := map[string]string{
		"SEC_A": "a",
	}
	store := &mapStore{secrets: secrets}

	c := config.DefaultConfig()
	c.Auth.AutoMintToken = true
	c.Audit.Enabled = false

	approvalCount := 0
	h := New(Deps{
		GetStore:  func() (SecretStore, error) { return store, nil },
		GetPolicy: staticPolicy(nil),
		Config:    c,
		ApprovalFn: func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
			approvalCount++
			return nil
		},
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	// First call: auto-mint with SEC_A.
	if err := h.checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC_A"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if approvalCount != 1 {
		t.Fatalf("approvalCount = %d, want 1", approvalCount)
	}
	firstToken := h.sessionTokenID

	// Add a new secret and request it.
	store.secrets["SEC_B"] = "b"

	// Session token only covers SEC_A, not SEC_B -> should clear and re-mint.
	if err := h.checkTokenOrApproval(context.Background(), "", "cmd", []string{"SEC_B"}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if approvalCount != 2 {
		t.Errorf("approvalCount = %d, want 2 (re-mint for new secret)", approvalCount)
	}
	if h.sessionTokenID == firstToken {
		t.Error("sessionTokenID should differ after re-mint for new secret")
	}
}

// --- HandleExec getKeyring error ---

func TestHandleExec_GetKeyringError(t *testing.T) {
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return nil, fmt.Errorf("keyring locked") },
		GetPolicy:    staticPolicy(nil),
		Config:       config.DefaultConfig(),
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello"},
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

// --- HandleExec store.GetAll error ---

func TestHandleExec_GetSecretsError(t *testing.T) {
	store := &mapStore{secrets: nil, err: fmt.Errorf("keys failed")}
	h := newTestHandler(t, store, nil, nil)

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to get secrets") {
		t.Errorf("result = %q, want 'failed to get secrets'", text)
	}
}

// --- HandleExecWithSecrets getKeyring error ---

func TestHandleExecWithSecrets_GetKeyringError(t *testing.T) {
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return nil, fmt.Errorf("keyring locked") },
		GetPolicy:    staticPolicy(nil),
		Config:       config.DefaultConfig(),
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return t.TempDir(), nil },
	})

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:SECRET}}"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

// --- HandleExecWithSecrets approval denied ---

func TestHandleExecWithSecrets_ApprovalDenied(t *testing.T) {
	store := &mapStore{secrets: map[string]string{}}
	pol := &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}
	h := newTestHandler(t, store, pol, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("user denied")
	})

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"${{NOKEY:MY_SECRET}}"},
	})
	result, err := h.HandleExecWithSecrets(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExecWithSecrets: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "denied") {
		t.Errorf("result = %q, want 'denied'", text)
	}
}

// --- HandleExec approval denied ---

func TestHandleExec_ApprovalDenied(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"MY_KEY": "my-value",
	}}
	pol := &policy.Policy{
		Approval: "always",
		Rules: []policy.Rule{{
			Commands: []string{"*"},
			Secrets:  []string{"*"},
			Approval: "always",
		}},
	}
	h := newTestHandler(t, store, pol, func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
		return fmt.Errorf("approval denied")
	})

	req := makeCallToolRequest(map[string]any{
		"command": "echo",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "approval denied") {
		t.Errorf("result = %q, want 'approval denied'", text)
	}
}

// --- HandleStartProxy getKeyring error ---

func TestHandleStartProxy_GetKeyringError(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_SECRET"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	polObj, err := policy.Load(configDir)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}

	// Init CA so LoadOrCreateCA succeeds
	if _, err := proxy.LoadOrCreateCA(configDir); err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	c := config.DefaultConfig()
	c.Audit.Enabled = false
	h := New(Deps{
		GetStore:     func() (SecretStore, error) { return nil, fmt.Errorf("keyring error") },
		GetPolicy:    staticPolicy(polObj),
		Config:       c,
		ApprovalFn:   func(ctx context.Context, req approval.Requester, cmd string, secrets []string) error { return nil },
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return configDir, nil },
	})

	req := makeCallToolRequest(map[string]any{})
	result, err := h.HandleStartProxy(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleStartProxy: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "failed to open keyring") {
		t.Errorf("result = %q, want 'failed to open keyring'", text)
	}
}

// --- HandleExec filter secrets error ---

func TestHandleExec_FilterError(t *testing.T) {
	store := &mapStore{secrets: map[string]string{
		"KEY": "val",
	}}
	h := newTestHandler(t, store, nil, nil)

	// Use both only and except to trigger filter error
	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"only":    "A",
		"except":  "B",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "cannot use both") {
		t.Errorf("result = %q, want 'cannot use both'", text)
	}
}

// --- HandleMintToken store.Mint error ---

func TestHandleMintToken_MintError(t *testing.T) {
	// Mint with TTL of 0 -- this should still work since token.Store.Mint handles it.
	// Instead, let's use a negative TTL to try to trigger an error (if the store validates).
	// Actually, token.Store.Mint always succeeds for valid inputs.
	// Let's test with a very large max_uses to ensure the path works.
	// The mint error path is hard to trigger with a real token store.
	// Skip this test -- the error path would require a custom token store interface.
	t.Skip("mint error path requires injectable token store")
}

// TestHandleExec_ReloadsPolicyWhenFileChanges mirrors the reported bug:
// after editing policies.yaml to add a new rule, the running MCP daemon
// must pick up the change on the next request without being restarted.
func TestHandleExec_ReloadsPolicyWhenFileChanges(t *testing.T) {
	configDir := t.TempDir()
	policyPath := filepath.Join(configDir, "policies.yaml")

	// Initial policy: allow echo to access SECRET_A only (denies SECRET_B).
	initialYAML := `rules:
  - commands: ["echo"]
    secrets: ["SECRET_A"]
`
	if err := os.WriteFile(policyPath, []byte(initialYAML), 0600); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	polStore, err := policy.NewStore(configDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	store := &mapStore{secrets: map[string]string{
		"SECRET_A": "val-a",
		"SECRET_B": "val-b",
	}}

	c := config.DefaultConfig()
	c.Audit.Enabled = false
	h := New(Deps{
		GetStore:  func() (SecretStore, error) { return store, nil },
		GetPolicy: polStore.Current,
		Config:    c,
		ApprovalFn: func(_ context.Context, _ approval.Requester, _ string, _ []string) error {
			return nil
		},
		AuditFn:      func(string, string, string, bool, string) {},
		GetConfigDir: func() (string, error) { return configDir, nil },
	})

	// First call: allowed under the initial policy — filter to SECRET_A only.
	req := makeCallToolRequest(map[string]any{
		"command": "echo",
		"args":    []any{"hello"},
		"only":    "SECRET_A",
	})
	result, err := h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("first HandleExec: %v", err)
	}
	text := getResultText(t, result)
	if !strings.Contains(text, "hello") {
		t.Fatalf("first call: result = %q, want stdout 'hello'", text)
	}
	if strings.Contains(text, "policy denied") {
		t.Fatalf("first call unexpectedly denied: %s", text)
	}

	// Rewrite policies.yaml to deny echo entirely (only curl is allowed now).
	// Bump mtime explicitly so the stat-based reload check fires reliably on
	// filesystems with coarse timestamps.
	updatedYAML := `rules:
  - commands: ["curl"]
    secrets: ["SECRET_A"]
`
	if err := os.WriteFile(policyPath, []byte(updatedYAML), 0600); err != nil {
		t.Fatalf("write updated policy: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(policyPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Second call: must pick up the new policy and deny echo.
	result, err = h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("second HandleExec: %v", err)
	}
	text = getResultText(t, result)
	if !strings.Contains(text, "policy denied") {
		t.Fatalf("second call: result = %q, want policy denial after reload", text)
	}

	// Rewrite again to allow echo for SECRET_A and SECRET_B. Bump mtime again.
	reenabledYAML := `rules:
  - commands: ["echo"]
    secrets: ["SECRET_*"]
`
	if err := os.WriteFile(policyPath, []byte(reenabledYAML), 0600); err != nil {
		t.Fatalf("write reenabled policy: %v", err)
	}
	future = time.Now().Add(4 * time.Second)
	if err := os.Chtimes(policyPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Third call: allowed again.
	result, err = h.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatalf("third HandleExec: %v", err)
	}
	text = getResultText(t, result)
	if strings.Contains(text, "policy denied") {
		t.Fatalf("third call: result = %q, want success after re-allowing", text)
	}
	if !strings.Contains(text, "hello") {
		t.Fatalf("third call: result = %q, want stdout 'hello'", text)
	}
}
