package apiclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/integration"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/token"
)

// auditRecord captures a single audit call.
type auditRecord struct {
	Op      string
	Target  string
	Secrets string
	Ok      bool
	ErrMsg  string
}

// staticPolicy returns a GetPolicy provider that always returns p.
func staticPolicy(p *policy.Policy) func() *policy.Policy {
	return func() *policy.Policy { return p }
}

func testDeps(secrets map[string]string) (integration.Deps, *[]auditRecord) {
	var audits []auditRecord
	return integration.Deps{
		GetSecret: func(name string) (string, error) {
			return secrets[name], nil
		},
		// GetPolicy nil → apiclient.Do treats as allow-all
		Requester: nil, // no approval needed with nil policy
		AuditFn: func(op, target, secretList string, ok bool, errMsg string) {
			audits = append(audits, auditRecord{op, target, secretList, ok, errMsg})
		},
	}, &audits
}

func TestDo_InjectsAuthHeaders(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	secrets := map[string]string{"MY_TOKEN": "secret-abc-123"}
	deps, _ := testDeps(secrets)

	mappings := []integration.SecretMapping{{
		SecretName: "MY_TOKEN",
		HeaderName: "Authorization",
		HeaderTmpl: "Bearer %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	body, code, err := c.Do(context.Background(), "GET", "/api/test", nil, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}
	if gotAuth != "Bearer secret-abc-123" {
		t.Fatalf("expected auth header 'Bearer secret-abc-123', got %q", gotAuth)
	}
	if body != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestDo_RedactsResponseBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`token is secret-abc-123 and more`))
	}))
	defer upstream.Close()

	secrets := map[string]string{"MY_TOKEN": "secret-abc-123"}
	deps, _ := testDeps(secrets)

	mappings := []integration.SecretMapping{{
		SecretName: "MY_TOKEN",
		HeaderName: "Authorization",
		HeaderTmpl: "Bearer %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	body, _, err := c.Do(context.Background(), "GET", "/data", nil, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(body, "secret-abc-123") {
		t.Fatalf("response body was not redacted: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:MY_TOKEN]") {
		t.Fatalf("expected redaction marker in body: %s", body)
	}
}

func TestDo_PolicyDenial(t *testing.T) {
	// Create a policy that only allows "other-cmd" to access "MY_TOKEN".
	pol := &policy.Policy{
		Rules: []policy.Rule{{
			Commands: []string{"other-cmd"},
			Secrets:  []string{"MY_TOKEN"},
		}},
	}

	deps, audits := testDeps(map[string]string{"MY_TOKEN": "val"})
	deps.GetPolicy = staticPolicy(pol)

	mappings := []integration.SecretMapping{{
		SecretName: "MY_TOKEN",
		HeaderName: "Authorization",
		HeaderTmpl: "Bearer %s",
	}}

	c := New("test", "http://unused", mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/", nil, nil)

	if err == nil {
		t.Fatal("expected policy denial error")
	}
	if !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("expected policy denial, got: %v", err)
	}
	if len(*audits) != 1 || (*audits)[0].Ok {
		t.Fatalf("expected one failed audit entry, got: %+v", *audits)
	}
}

func TestDo_ExtraHeaders(t *testing.T) {
	var gotAccept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	deps, _ := testDeps(map[string]string{"TK": "val"})
	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/", nil, map[string]string{
		"Accept": "application/json",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAccept != "application/json" {
		t.Fatalf("expected Accept header, got %q", gotAccept)
	}
}

func TestDo_AuditCalledOnSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	deps, audits := testDeps(map[string]string{"TK": "val"})
	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/health", nil, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*audits) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(*audits))
	}
	a := (*audits)[0]
	if a.Op != "mcp:integration:test" {
		t.Fatalf("unexpected audit op: %s", a.Op)
	}
	if a.Target != "GET /health" {
		t.Fatalf("unexpected audit target: %s", a.Target)
	}
	if !a.Ok {
		t.Fatalf("expected audit ok=true")
	}
}

func TestDo_AuditCalledOnNon2xx(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("error"))
	}))
	defer upstream.Close()

	deps, audits := testDeps(map[string]string{"TK": "val"})
	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	body, code, err := c.Do(context.Background(), "POST", "/fail", nil, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 500 {
		t.Fatalf("expected status 500, got %d", code)
	}
	if body != "error" {
		t.Fatalf("unexpected body: %s", body)
	}
	if len(*audits) != 1 || (*audits)[0].Ok {
		t.Fatalf("expected one failed audit entry, got: %+v", *audits)
	}
}

func TestDo_PostWithBody(t *testing.T) {
	var gotBody string
	var gotMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer upstream.Close()

	deps, _ := testDeps(map[string]string{"TK": "val"})
	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	body, code, err := c.Do(context.Background(), "POST", "/items",
		strings.NewReader(`{"name":"test"}`), map[string]string{
			"Content-Type": "application/json",
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotBody != `{"name":"test"}` {
		t.Fatalf("unexpected request body: %s", gotBody)
	}
	if code != 201 {
		t.Fatalf("expected status 201, got %d", code)
	}
	if body != `{"id":1}` {
		t.Fatalf("unexpected response body: %s", body)
	}
}

// --- Additional coverage tests ---

func TestDo_SecretFetchError(t *testing.T) {
	deps := integration.Deps{
		GetSecret: func(name string) (string, error) {
			return "", fmt.Errorf("secret not found: %s", name)
		},
		// GetPolicy nil → allow-all
	}

	mappings := []integration.SecretMapping{{
		SecretName: "MISSING",
		HeaderName: "Authorization",
		HeaderTmpl: "Bearer %s",
	}}

	c := New("test", "http://unused", mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	if !strings.Contains(err.Error(), "failed to get secret") {
		t.Fatalf("expected 'failed to get secret' error, got: %v", err)
	}
}

func TestDo_HTTPTransportError(t *testing.T) {
	deps, _ := testDeps(map[string]string{"TK": "val"})
	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	// Use an invalid URL that will cause a transport error
	c := New("test", "http://127.0.0.1:1", mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/fail", nil, nil)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !strings.Contains(err.Error(), "HTTP request failed") {
		t.Fatalf("expected HTTP request failed error, got: %v", err)
	}
}

func TestDo_NoAuditFunction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	deps := integration.Deps{
		GetSecret: func(name string) (string, error) { return "val", nil },
		AuditFn:   nil, // No audit function
	}

	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	_, code, err := c.Do(context.Background(), "GET", "/", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestDo_TokenBasedAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	deps, audits := testDeps(map[string]string{"TK": "val"})
	deps.UseToken = func(tokenID string, secretNames []string) error {
		if tokenID != "test-token-id" {
			return fmt.Errorf("unexpected token: %s", tokenID)
		}
		return nil
	}

	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	ctx := token.WithTokenID(context.Background(), "test-token-id")
	_, code, err := c.Do(ctx, "GET", "/", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if len(*audits) != 1 || !(*audits)[0].Ok {
		t.Fatalf("expected 1 successful audit, got: %+v", *audits)
	}
}

func TestDo_RequestBuildError(t *testing.T) {
	deps, audits := testDeps(map[string]string{"TK": "val"})
	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", "http://valid", mappings, deps)
	// Use an invalid HTTP method to trigger NewRequestWithContext error
	_, _, err := c.Do(context.Background(), "BAD METHOD", "/path", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
	if !strings.Contains(err.Error(), "failed to build request") {
		t.Fatalf("expected 'failed to build request' error, got: %v", err)
	}
	// Audit should have been called with the error
	if len(*audits) != 1 || (*audits)[0].Ok {
		t.Fatalf("expected one failed audit entry, got: %+v", *audits)
	}
}

func TestDo_ApprovalRequired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer upstream.Close()

	// Create a policy where "nokey:integration:test" is allowed with approval required.
	pol := &policy.Policy{
		Rules: []policy.Rule{{
			Commands: []string{"nokey:integration:test"},
			Secrets:  []string{"TK"},
			Approval: policy.ApprovalAlways,
		}},
	}

	deps, audits := testDeps(map[string]string{"TK": "val"})
	deps.GetPolicy = staticPolicy(pol)
	// No Requester set, so approval.Request will fail
	deps.Requester = nil

	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", upstream.URL, mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/", nil, nil)
	// approval.Request with nil requester should fail
	if err == nil {
		t.Fatal("expected approval error")
	}
	if len(*audits) < 1 || (*audits)[0].Ok {
		t.Fatalf("expected failed audit entry, got: %+v", *audits)
	}
}

func TestDo_SecretFetchErrorWithAudit(t *testing.T) {
	var audits []auditRecord
	deps := integration.Deps{
		GetSecret: func(name string) (string, error) {
			return "", fmt.Errorf("keyring locked")
		},
		AuditFn: func(op, target, secretList string, ok bool, errMsg string) {
			audits = append(audits, auditRecord{op, target, secretList, ok, errMsg})
		},
	}

	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", "http://unused", mappings, deps)
	_, _, err := c.Do(context.Background(), "GET", "/api", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	// Verify audit was called with failure
	if len(audits) != 1 || audits[0].Ok {
		t.Fatalf("expected failed audit, got: %+v", audits)
	}
	if audits[0].Target != "GET /api" {
		t.Fatalf("expected target 'GET /api', got %q", audits[0].Target)
	}
}

func TestDo_TokenAuthFailure(t *testing.T) {
	deps, _ := testDeps(map[string]string{"TK": "val"})
	deps.UseToken = func(tokenID string, secretNames []string) error {
		return fmt.Errorf("token expired")
	}

	mappings := []integration.SecretMapping{{
		SecretName: "TK",
		HeaderName: "Authorization",
		HeaderTmpl: "token %s",
	}}

	c := New("test", "http://unused", mappings, deps)
	ctx := token.WithTokenID(context.Background(), "bad-token")
	_, _, err := c.Do(ctx, "GET", "/", nil, nil)
	if err == nil {
		t.Fatal("expected token error")
	}
	if !strings.Contains(err.Error(), "token invalid") {
		t.Fatalf("expected 'token invalid' error, got: %v", err)
	}
}
