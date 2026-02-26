package apiclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/integration"
	"github.com/nokey-ai/nokey/internal/redact"
)

// Client performs HTTP requests with automatic secret injection, policy
// enforcement, approval gating, response redaction, and audit logging.
type Client struct {
	integrationName string
	baseURL         string
	mappings        []integration.SecretMapping
	deps            integration.Deps
	http            *http.Client
}

// New creates a Client for the given integration.
func New(integrationName, baseURL string, mappings []integration.SecretMapping, deps integration.Deps) *Client {
	return &Client{
		integrationName: integrationName,
		baseURL:         baseURL,
		mappings:        mappings,
		deps:            deps,
		http:            &http.Client{},
	}
}

// Do executes an HTTP request through the full security pipeline:
// policy check → approval → secret fetch → header injection → HTTP call → redact → audit.
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader,
	extraHeaders map[string]string) (responseBody string, statusCode int, err error) {

	command := "nokey:integration:" + c.integrationName
	target := method + " " + path

	// Collect secret names from mappings.
	secretNames := make([]string, len(c.mappings))
	for i, m := range c.mappings {
		secretNames[i] = m.SecretName
	}

	// 1. Policy check.
	if err := c.deps.Policy.Check(command, secretNames); err != nil {
		c.audit(target, secretNames, false, err.Error())
		return "", 0, err
	}

	// 2. Approval gateway.
	if c.deps.Policy.RequiresApproval(command, secretNames) {
		if err := requestApproval(ctx, c.deps.Requester, command, secretNames); err != nil {
			c.audit(target, secretNames, false, err.Error())
			return "", 0, err
		}
	}

	// 3. Fetch secrets.
	secrets := make(map[string]string, len(c.mappings))
	for _, m := range c.mappings {
		val, err := c.deps.GetSecret(m.SecretName)
		if err != nil {
			c.audit(target, secretNames, false, err.Error())
			return "", 0, fmt.Errorf("failed to get secret %q: %w", m.SecretName, err)
		}
		secrets[m.SecretName] = val
	}

	// 4. Build request.
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		c.audit(target, secretNames, false, err.Error())
		return "", 0, fmt.Errorf("failed to build request: %w", err)
	}

	// Inject auth headers from mappings.
	for _, m := range c.mappings {
		headerVal := fmt.Sprintf(m.HeaderTmpl, secrets[m.SecretName])
		req.Header.Set(m.HeaderName, headerVal)
	}

	// Add extra headers.
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	// 5. Execute HTTP call.
	resp, err := c.http.Do(req)
	if err != nil {
		c.audit(target, secretNames, false, err.Error())
		return "", 0, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// 6. Read and redact response body.
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.audit(target, secretNames, false, err.Error())
		return "", resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	redacted := redact.RedactBytes(respBytes, secrets)

	// 7. Audit.
	ok := resp.StatusCode >= 200 && resp.StatusCode < 400
	errMsg := ""
	if !ok {
		errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	c.audit(target, secretNames, ok, errMsg)

	return string(redacted), resp.StatusCode, nil
}

func (c *Client) audit(target string, secretNames []string, ok bool, errMsg string) {
	if c.deps.AuditFn != nil {
		c.deps.AuditFn(
			"mcp:integration:"+c.integrationName,
			target,
			strings.Join(secretNames, ","),
			ok,
			errMsg,
		)
	}
}

// requestApproval sends an MCP elicitation prompt asking the user to approve
// secret access. Returns nil if approved, an error otherwise.
func requestApproval(ctx context.Context, requester *server.MCPServer, command string, secretNames []string) error {
	msg := fmt.Sprintf(
		"nokey: %q wants to access secret(s): %s\n\nDo you approve?",
		command, strings.Join(secretNames, ", "),
	)

	result, err := requester.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: msg,
			RequestedSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"approve": map[string]any{
						"type":        "boolean",
						"description": "Approve secret access",
					},
				},
			},
		},
	})
	if err != nil {
		if errors.Is(err, server.ErrElicitationNotSupported) {
			return fmt.Errorf("approval required but client does not support elicitation prompts")
		}
		if errors.Is(err, server.ErrNoActiveSession) {
			return fmt.Errorf("approval required but no active MCP session")
		}
		return fmt.Errorf("approval request failed: %w", err)
	}

	switch result.Action {
	case mcp.ElicitationResponseActionAccept:
		return nil
	case mcp.ElicitationResponseActionDecline:
		return fmt.Errorf("user declined secret access for %q", command)
	case mcp.ElicitationResponseActionCancel:
		return fmt.Errorf("user cancelled secret access for %q", command)
	default:
		return fmt.Errorf("unexpected elicitation response: %s", result.Action)
	}
}
