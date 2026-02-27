package apiclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/integration"
	"github.com/nokey-ai/nokey/internal/policy"
)

// auditRecord captures a single audit call.
type auditRecord struct {
	Op      string
	Target  string
	Secrets string
	Ok      bool
	ErrMsg  string
}

func testDeps(secrets map[string]string) (integration.Deps, *[]auditRecord) {
	var audits []auditRecord
	return integration.Deps{
		GetSecret: func(name string) (string, error) {
			return secrets[name], nil
		},
		Policy:    nil, // nil policy allows everything
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
	deps.Policy = pol

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
