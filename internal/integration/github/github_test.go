package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/integration"
	"github.com/nokey-ai/nokey/internal/integration/apiclient"
)

// testClient creates an apiclient.Client that points at the given httptest.Server.
func testClient(ts *httptest.Server) *apiclient.Client {
	deps := integration.Deps{
		GetSecret: func(name string) (string, error) {
			return "test-token-value", nil
		},
		Policy:    nil,
		Requester: nil,
		AuditFn:   func(op, target, secrets string, ok bool, errMsg string) {},
	}
	return apiclient.New("github", ts.URL, secretMappings, deps)
}

// callTool is a test helper that builds a CallToolRequest and calls the handler.
func callTool(t *testing.T, tool server.ServerTool, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = tool.Tool.Name
	req.Params.Arguments = args

	result, err := tool.Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned Go error: %v", err)
	}
	return result
}

func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty content in result")
	}
	tc, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

// --- github_api tests ---

func TestGitHubAPI_GET(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotAccept string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(200)
		w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGitHubAPI(client)

	result := callTool(t, tool, map[string]any{
		"method": "GET",
		"path":   "/user",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotMethod != "GET" {
		t.Fatalf("expected GET, got %s", gotMethod)
	}
	if gotPath != "/user" {
		t.Fatalf("expected /user, got %s", gotPath)
	}
	if gotAuth != "Bearer test-token-value" {
		t.Fatalf("expected Bearer auth, got %q", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Fatalf("expected GitHub accept header, got %q", gotAccept)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "octocat") {
		t.Fatalf("expected response to contain octocat, got: %s", text)
	}
}

func TestGitHubAPI_POST(t *testing.T) {
	var gotBody string
	var gotContentType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(201)
		w.Write([]byte(`{"id":1}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGitHubAPI(client)

	result := callTool(t, tool, map[string]any{
		"method": "POST",
		"path":   "/repos/owner/repo/issues",
		"body":   `{"title":"test"}`,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected JSON content type, got %q", gotContentType)
	}
	if gotBody != `{"title":"test"}` {
		t.Fatalf("unexpected body: %s", gotBody)
	}
}

func TestGitHubAPI_MissingMethod(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGitHubAPI(client)

	result := callTool(t, tool, map[string]any{"path": "/user"})
	if !result.IsError {
		t.Fatal("expected error for missing method")
	}
}

func TestGitHubAPI_MissingPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGitHubAPI(client)

	result := callTool(t, tool, map[string]any{"method": "GET"})
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}
}

func TestGitHubAPI_Non2xxReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGitHubAPI(client)

	result := callTool(t, tool, map[string]any{
		"method": "GET",
		"path":   "/repos/noexist/noexist",
	})

	if !result.IsError {
		t.Fatal("expected error result for 404")
	}
	text := resultText(t, result)
	if !strings.Contains(text, "404") {
		t.Fatalf("expected 404 in error, got: %s", text)
	}
}

func TestGitHubAPI_RedactsToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the token in the response to test redaction.
		w.Write([]byte(`{"token":"test-token-value"}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGitHubAPI(client)

	result := callTool(t, tool, map[string]any{
		"method": "GET",
		"path":   "/echo",
	})

	text := resultText(t, result)
	if strings.Contains(text, "test-token-value") {
		t.Fatalf("token was not redacted from response: %s", text)
	}
	if !strings.Contains(text, "[REDACTED:GITHUB_TOKEN]") {
		t.Fatalf("expected redaction marker: %s", text)
	}
}

// --- github_create_issue tests ---

func TestCreateIssue(t *testing.T) {
	var gotMethod, gotPath string
	var gotPayload map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotPayload)
		w.WriteHeader(201)
		w.Write([]byte(`{"number":42}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolCreateIssue(client)

	result := callTool(t, tool, map[string]any{
		"owner":     "octocat",
		"repo":      "hello",
		"title":     "Bug report",
		"body":      "Something broke",
		"labels":    []any{"bug", "urgent"},
		"assignees": []any{"octocat"},
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotMethod != "POST" {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/repos/octocat/hello/issues" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotPayload["title"] != "Bug report" {
		t.Fatalf("unexpected title: %v", gotPayload["title"])
	}
	if gotPayload["body"] != "Something broke" {
		t.Fatalf("unexpected body: %v", gotPayload["body"])
	}
}

func TestCreateIssue_MissingRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolCreateIssue(client)

	result := callTool(t, tool, map[string]any{"owner": "x", "repo": "y"})
	if !result.IsError {
		t.Fatal("expected error for missing title")
	}
}

// --- github_create_pr tests ---

func TestCreatePR(t *testing.T) {
	var gotPath string
	var gotPayload map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotPayload)
		w.WriteHeader(201)
		w.Write([]byte(`{"number":1}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolCreatePR(client)

	result := callTool(t, tool, map[string]any{
		"owner": "octocat",
		"repo":  "hello",
		"title": "Add feature",
		"head":  "feature-branch",
		"base":  "main",
		"body":  "PR description",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotPath != "/repos/octocat/hello/pulls" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotPayload["head"] != "feature-branch" {
		t.Fatalf("unexpected head: %v", gotPayload["head"])
	}
	if gotPayload["base"] != "main" {
		t.Fatalf("unexpected base: %v", gotPayload["base"])
	}
}

func TestCreatePR_MissingRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolCreatePR(client)

	result := callTool(t, tool, map[string]any{"owner": "x", "repo": "y", "title": "t"})
	if !result.IsError {
		t.Fatal("expected error for missing head/base")
	}
}

// --- github_list_issues tests ---

func TestListIssues(t *testing.T) {
	var gotPath, gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`[{"number":1}]`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolListIssues(client)

	result := callTool(t, tool, map[string]any{
		"owner":    "octocat",
		"repo":     "hello",
		"state":    "closed",
		"labels":   "bug,urgent",
		"per_page": float64(10),
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotPath != "/repos/octocat/hello/issues" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if !strings.Contains(gotQuery, "state=closed") {
		t.Fatalf("expected state=closed in query: %s", gotQuery)
	}
	if !strings.Contains(gotQuery, "per_page=10") {
		t.Fatalf("expected per_page=10 in query: %s", gotQuery)
	}
}

func TestListIssues_MissingRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolListIssues(client)

	result := callTool(t, tool, map[string]any{"owner": "x"})
	if !result.IsError {
		t.Fatal("expected error for missing repo")
	}
}

// --- github_list_prs tests ---

func TestListPRs(t *testing.T) {
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`[{"number":1}]`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolListPRs(client)

	result := callTool(t, tool, map[string]any{
		"owner": "octocat",
		"repo":  "hello",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotPath != "/repos/octocat/hello/pulls" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
}

// --- github_get_file tests ---

func TestGetFile(t *testing.T) {
	var gotPath, gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{"name":"README.md","content":"aGVsbG8="}`))
	}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGetFile(client)

	result := callTool(t, tool, map[string]any{
		"owner": "octocat",
		"repo":  "hello",
		"path":  "README.md",
		"ref":   "main",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	if gotPath != "/repos/octocat/hello/contents/README.md" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotQuery != "ref=main" {
		t.Fatalf("expected ref=main query, got: %s", gotQuery)
	}
}

func TestGetFile_MissingRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := testClient(ts)
	tool := toolGetFile(client)

	result := callTool(t, tool, map[string]any{"owner": "x", "repo": "y"})
	if !result.IsError {
		t.Fatal("expected error for missing path")
	}
}

// --- Integration interface tests ---

func TestGitHubIntegration_ImplementsInterface(t *testing.T) {
	g := &GitHub{}
	if g.Name() != "github" {
		t.Fatalf("unexpected name: %s", g.Name())
	}
	if len(g.SecretMappings()) != 1 {
		t.Fatalf("expected 1 secret mapping, got %d", len(g.SecretMappings()))
	}
	if g.SecretMappings()[0].SecretName != "GITHUB_TOKEN" {
		t.Fatalf("unexpected secret: %s", g.SecretMappings()[0].SecretName)
	}
}

func TestGitHubIntegration_ToolCount(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	deps := integration.Deps{
		GetSecret: func(name string) (string, error) { return "tok", nil },
		AuditFn:   func(op, target, secrets string, ok bool, errMsg string) {},
	}
	// Override baseURL is not possible directly, so just verify tool count from the struct.
	g := &GitHub{}
	// We can't easily test Tools() without overriding baseURL, but we verify
	// it returns the right number of tools.
	tools := g.Tools(deps)
	if len(tools) != 6 {
		t.Fatalf("expected 6 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Tool.Name] = true
	}

	expected := []string{
		"github_api", "github_create_issue", "github_create_pr",
		"github_list_issues", "github_list_prs", "github_get_file",
	}
	for _, name := range expected {
		if !names[name] {
			t.Fatalf("missing tool: %s", name)
		}
	}
}
