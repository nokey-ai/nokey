package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/integration"
	"github.com/nokey-ai/nokey/internal/integration/apiclient"
)

const (
	baseURL    = "https://api.github.com"
	secretName = "GITHUB_TOKEN" //nolint:gosec // Not a hardcoded credential, just an env var name
)

var secretMappings = []integration.SecretMapping{{
	SecretName: secretName,
	HeaderName: "Authorization",
	HeaderTmpl: "Bearer %s",
}}

// GitHub implements the integration.Integration interface.
type GitHub struct{}

func (g *GitHub) Name() string                                { return "github" }
func (g *GitHub) Description() string                         { return "GitHub API integration with automatic token injection" }
func (g *GitHub) SecretMappings() []integration.SecretMapping { return secretMappings }

func (g *GitHub) Tools(deps integration.Deps) []server.ServerTool {
	client := apiclient.New("github", baseURL, secretMappings, deps)
	return []server.ServerTool{
		toolGitHubAPI(client),
		toolCreateIssue(client),
		toolCreatePR(client),
		toolListIssues(client),
		toolListPRs(client),
		toolGetFile(client),
	}
}

func init() {
	integration.Register(&GitHub{})
}

// defaultHeaders returns the standard headers for GitHub API requests.
func defaultHeaders(accept string) map[string]string {
	if accept == "" {
		accept = "application/vnd.github+json"
	}
	return map[string]string{
		"Accept":               accept,
		"X-GitHub-Api-Version": "2022-11-28",
	}
}

// toolResult wraps a successful API response into an MCP tool result.
// Non-2xx responses are returned as tool errors.
func toolResult(body string, code int, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if code >= 400 {
		return mcp.NewToolResultError(fmt.Sprintf("GitHub API error (HTTP %d): %s", code, body)), nil
	}
	return mcp.NewToolResultText(body), nil
}

// --- github_api: flexible tool for any endpoint ---

func toolGitHubAPI(client *apiclient.Client) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("github_api",
			mcp.WithDescription(
				"Call any GitHub API endpoint with automatic token injection. "+
					"Response is automatically redacted to remove secret values.",
			),
			mcp.WithString("method",
				mcp.Required(),
				mcp.Description("HTTP method (GET, POST, PUT, PATCH, DELETE)"),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("API path, e.g. /user or /repos/owner/repo/issues"),
			),
			mcp.WithString("body",
				mcp.Description("Request body as JSON string (for POST/PUT/PATCH)"),
			),
			mcp.WithString("accept",
				mcp.Description("Accept header value (default: application/vnd.github+json)"),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			method := strings.ToUpper(req.GetString("method", ""))
			path := req.GetString("path", "")
			bodyStr := req.GetString("body", "")
			accept := req.GetString("accept", "")

			if method == "" {
				return mcp.NewToolResultError("parameter 'method' is required"), nil
			}
			if path == "" {
				return mcp.NewToolResultError("parameter 'path' is required"), nil
			}

			var bodyReader *strings.Reader
			if bodyStr != "" {
				bodyReader = strings.NewReader(bodyStr)
			}

			headers := defaultHeaders(accept)
			if bodyStr != "" {
				headers["Content-Type"] = "application/json"
			}

			var body string
			var code int
			var err error
			if bodyReader != nil {
				body, code, err = client.Do(ctx, method, path, bodyReader, headers)
			} else {
				body, code, err = client.Do(ctx, method, path, nil, headers)
			}
			return toolResult(body, code, err)
		},
	}
}

// --- github_create_issue ---

func toolCreateIssue(client *apiclient.Client) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("github_create_issue",
			mcp.WithDescription("Create a GitHub issue with automatic token injection."),
			mcp.WithString("owner", mcp.Required(), mcp.Description("Repository owner")),
			mcp.WithString("repo", mcp.Required(), mcp.Description("Repository name")),
			mcp.WithString("title", mcp.Required(), mcp.Description("Issue title")),
			mcp.WithString("body", mcp.Description("Issue body (Markdown)")),
			mcp.WithArray("labels", mcp.WithStringItems(), mcp.Description("Labels to apply")),
			mcp.WithArray("assignees", mcp.WithStringItems(), mcp.Description("GitHub usernames to assign")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner := req.GetString("owner", "")
			repo := req.GetString("repo", "")
			title := req.GetString("title", "")

			if owner == "" || repo == "" || title == "" {
				return mcp.NewToolResultError("parameters 'owner', 'repo', and 'title' are required"), nil
			}

			payload := map[string]any{"title": title}
			if b := req.GetString("body", ""); b != "" {
				payload["body"] = b
			}
			if l := req.GetStringSlice("labels", nil); len(l) > 0 {
				payload["labels"] = l
			}
			if a := req.GetStringSlice("assignees", nil); len(a) > 0 {
				payload["assignees"] = a
			}

			jsonBody, _ := json.Marshal(payload)
			path := fmt.Sprintf("/repos/%s/%s/issues", owner, repo)

			body, code, err := client.Do(ctx, "POST", path, strings.NewReader(string(jsonBody)), defaultHeaders(""))
			return toolResult(body, code, err)
		},
	}
}

// --- github_create_pr ---

func toolCreatePR(client *apiclient.Client) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("github_create_pr",
			mcp.WithDescription("Create a GitHub pull request with automatic token injection."),
			mcp.WithString("owner", mcp.Required(), mcp.Description("Repository owner")),
			mcp.WithString("repo", mcp.Required(), mcp.Description("Repository name")),
			mcp.WithString("title", mcp.Required(), mcp.Description("PR title")),
			mcp.WithString("body", mcp.Description("PR description (Markdown)")),
			mcp.WithString("head", mcp.Required(), mcp.Description("Branch containing changes")),
			mcp.WithString("base", mcp.Required(), mcp.Description("Branch to merge into")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner := req.GetString("owner", "")
			repo := req.GetString("repo", "")
			title := req.GetString("title", "")
			head := req.GetString("head", "")
			base := req.GetString("base", "")

			if owner == "" || repo == "" || title == "" || head == "" || base == "" {
				return mcp.NewToolResultError("parameters 'owner', 'repo', 'title', 'head', and 'base' are required"), nil
			}

			payload := map[string]any{
				"title": title,
				"head":  head,
				"base":  base,
			}
			if b := req.GetString("body", ""); b != "" {
				payload["body"] = b
			}

			jsonBody, _ := json.Marshal(payload)
			path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)

			body, code, err := client.Do(ctx, "POST", path, strings.NewReader(string(jsonBody)), defaultHeaders(""))
			return toolResult(body, code, err)
		},
	}
}

// --- github_list_issues ---

func toolListIssues(client *apiclient.Client) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("github_list_issues",
			mcp.WithDescription("List issues in a GitHub repository with automatic token injection."),
			mcp.WithString("owner", mcp.Required(), mcp.Description("Repository owner")),
			mcp.WithString("repo", mcp.Required(), mcp.Description("Repository name")),
			mcp.WithString("state", mcp.Description("Filter by state: open, closed, all (default: open)")),
			mcp.WithString("labels", mcp.Description("Comma-separated list of label names to filter by")),
			mcp.WithNumber("per_page", mcp.Description("Results per page (default: 30, max: 100)")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner := req.GetString("owner", "")
			repo := req.GetString("repo", "")

			if owner == "" || repo == "" {
				return mcp.NewToolResultError("parameters 'owner' and 'repo' are required"), nil
			}

			path := fmt.Sprintf("/repos/%s/%s/issues", owner, repo)
			params := buildQuery(req, "state", "labels", "per_page")
			if params != "" {
				path += "?" + params
			}

			body, code, err := client.Do(ctx, "GET", path, nil, defaultHeaders(""))
			return toolResult(body, code, err)
		},
	}
}

// --- github_list_prs ---

func toolListPRs(client *apiclient.Client) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("github_list_prs",
			mcp.WithDescription("List pull requests in a GitHub repository with automatic token injection."),
			mcp.WithString("owner", mcp.Required(), mcp.Description("Repository owner")),
			mcp.WithString("repo", mcp.Required(), mcp.Description("Repository name")),
			mcp.WithString("state", mcp.Description("Filter by state: open, closed, all (default: open)")),
			mcp.WithNumber("per_page", mcp.Description("Results per page (default: 30, max: 100)")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner := req.GetString("owner", "")
			repo := req.GetString("repo", "")

			if owner == "" || repo == "" {
				return mcp.NewToolResultError("parameters 'owner' and 'repo' are required"), nil
			}

			path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)
			params := buildQuery(req, "state", "per_page")
			if params != "" {
				path += "?" + params
			}

			body, code, err := client.Do(ctx, "GET", path, nil, defaultHeaders(""))
			return toolResult(body, code, err)
		},
	}
}

// --- github_get_file ---

func toolGetFile(client *apiclient.Client) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("github_get_file",
			mcp.WithDescription("Get a file's contents from a GitHub repository with automatic token injection."),
			mcp.WithString("owner", mcp.Required(), mcp.Description("Repository owner")),
			mcp.WithString("repo", mcp.Required(), mcp.Description("Repository name")),
			mcp.WithString("path", mcp.Required(), mcp.Description("File path within the repository")),
			mcp.WithString("ref", mcp.Description("Git ref (branch, tag, or SHA; default: default branch)")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			owner := req.GetString("owner", "")
			repo := req.GetString("repo", "")
			filePath := req.GetString("path", "")

			if owner == "" || repo == "" || filePath == "" {
				return mcp.NewToolResultError("parameters 'owner', 'repo', and 'path' are required"), nil
			}

			apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, filePath)
			params := buildQuery(req, "ref")
			if params != "" {
				apiPath += "?" + params
			}

			body, code, err := client.Do(ctx, "GET", apiPath, nil, defaultHeaders(""))
			return toolResult(body, code, err)
		},
	}
}

// buildQuery constructs a URL query string from request params that have non-default values.
func buildQuery(req mcp.CallToolRequest, keys ...string) string {
	var parts []string
	for _, key := range keys {
		if key == "per_page" {
			v := req.GetInt(key, 0)
			if v > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", key, v))
			}
		} else {
			v := req.GetString(key, "")
			if v != "" {
				parts = append(parts, fmt.Sprintf("%s=%s", key, v))
			}
		}
	}
	return strings.Join(parts, "&")
}
