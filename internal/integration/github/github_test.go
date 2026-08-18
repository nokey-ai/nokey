package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		// GetPolicy nil → apiclient.Do treats as allow-all
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
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
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
		_, _ = w.Write([]byte(`{"id":1}`))
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
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
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
		_, _ = w.Write([]byte(`{"token":"test-token-value"}`))
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
		_ = json.Unmarshal(b, &gotPayload)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"number":42}`))
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
		_ = json.Unmarshal(b, &gotPayload)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"number":1}`))
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
		_, _ = w.Write([]byte(`[{"number":1}]`))
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
		_, _ = w.Write([]byte(`[{"number":1}]`))
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
		_, _ = w.Write([]byte(`{"name":"README.md","content":"aGVsbG8="}`))
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

// --- URL escaping of model-supplied parameters ---

func TestBuildQuery_EscapesValues(t *testing.T) {
	tool := toolListIssues(nil)
	req := mcp.CallToolRequest{}
	req.Params.Name = tool.Tool.Name
	req.Params.Arguments = map[string]any{
		"state":  "open&per_page=100",
		"labels": "bug#frag",
	}

	got := buildQuery(req, "state", "labels", "per_page")

	parsed, err := url.ParseQuery(got)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", got, err)
	}
	if v := parsed.Get("state"); v != "open&per_page=100" {
		t.Errorf("state = %q, want the value kept whole", v)
	}
	if parsed.Has("per_page") {
		t.Errorf("per_page was injected via the state value: %q", got)
	}
	if v := parsed.Get("labels"); v != "bug#frag" {
		t.Errorf("labels = %q, want the value kept whole", v)
	}
}

// TestListIssues_QueryInjection covers the end-to-end path: a state value
// carrying extra parameters must arrive as one parameter, not as several.
func TestListIssues_QueryInjection(t *testing.T) {
	var gotQuery url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	callTool(t, toolListIssues(testClient(ts)), map[string]any{
		"owner": "octocat",
		"repo":  "hello",
		"state": "open&per_page=100",
	})

	if got := gotQuery.Get("state"); got != "open&per_page=100" {
		t.Errorf("state = %q, want the injected value kept whole", got)
	}
	if gotQuery.Has("per_page") {
		t.Errorf("per_page reached the API via injection: %v", gotQuery)
	}
}

func TestOwnerRepoAreEscaped(t *testing.T) {
	// Assert on RequestURI, the raw form on the wire. r.URL.Path is decoded,
	// so an escaped %2F reads back as "/" there and would hide the escaping.
	var gotURI, gotRawQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		gotRawQuery = r.URL.RawQuery
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	callTool(t, toolListIssues(testClient(ts)), map[string]any{
		"owner": "octocat/../../user?x=1",
		"repo":  "hello",
	})

	want := "/repos/octocat%2F..%2F..%2Fuser%3Fx=1/hello/issues"
	if gotURI != want {
		t.Errorf("request URI = %q, want %q — owner must stay one path segment", gotURI, want)
	}
	if gotRawQuery != "" {
		t.Errorf("owner started a query string: %q", gotRawQuery)
	}
}

func TestEscapeFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"simple", "README.md", "README.md", false},
		{"nested keeps separators", "src/main.go", "src/main.go", false},
		{"leading slash trimmed", "/src/main.go", "src/main.go", false},
		{"space escaped", "docs/my file.md", "docs/my%20file.md", false},
		{"query char escaped", "a?ref=x", "a%3Fref=x", false},
		{"fragment char escaped", "a#frag", "a%23frag", false},
		{"ampersand escaped", "a&b", "a&b", false},
		{"parent traversal rejected", "../../../user", "", true},
		{"traversal mid-path rejected", "src/../../user", "", true},
		{"dot segment rejected", "./x", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := escapeFilePath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("escapeFilePath(%q) = %q, want error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("escapeFilePath(%q): %v", tt.path, err)
			}
			if got != tt.want {
				t.Errorf("escapeFilePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestGetFile_PathInjection(t *testing.T) {
	var gotURI, gotRawQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		gotRawQuery = r.URL.RawQuery
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	callTool(t, toolGetFile(testClient(ts)), map[string]any{
		"owner": "octocat",
		"repo":  "hello",
		"path":  "secret?ref=evil#frag",
	})

	want := "/repos/octocat/hello/contents/secret%3Fref=evil%23frag"
	if gotURI != want {
		t.Errorf("request URI = %q, want %q — the ? and # must not split the URL", gotURI, want)
	}
	if gotRawQuery != "" {
		t.Errorf("file path started a query string: %q", gotRawQuery)
	}
}

func TestGetFile_RejectsTraversal(t *testing.T) {
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(200)
	}))
	defer ts.Close()

	result := callTool(t, toolGetFile(testClient(ts)), map[string]any{
		"owner": "octocat",
		"repo":  "hello",
		"path":  "../../../user",
	})

	if !result.IsError {
		t.Error("expected traversal in the file path to be refused")
	}
	if hit {
		t.Error("request reached the API despite a rejected path")
	}
}
