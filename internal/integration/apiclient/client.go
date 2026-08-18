package apiclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/integration"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/redact"
	"github.com/nokey-ai/nokey/internal/token"
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
		http:            &http.Client{Timeout: 30 * time.Second},
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

	// Resolve the current policy via the injected provider. A nil provider
	// or a nil returned Policy means allow-all — (*Policy).Check and friends
	// are nil-safe.
	var pol *policy.Policy
	if c.deps.GetPolicy != nil {
		pol = c.deps.GetPolicy()
	}

	// 1. Policy check.
	if err := pol.Check(command, secretNames); err != nil {
		c.audit(target, secretNames, false, err.Error())
		return "", 0, err
	}

	// 2. Token or approval gateway.
	tokenUsed := false
	if tokenID, ok := token.TokenIDFromContext(ctx); ok && c.deps.UseToken != nil {
		if err := c.deps.UseToken(tokenID, secretNames); err != nil {
			c.audit(target, secretNames, false, err.Error())
			return "", 0, fmt.Errorf("token invalid: %w", err)
		}
		tokenUsed = true
	}
	if !tokenUsed {
		if pol.RequiresApproval(command, secretNames) {
			if err := approval.Request(ctx, c.deps.Requester, command, secretNames); err != nil {
				c.audit(target, secretNames, false, err.Error())
				return "", 0, err
			}
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
	reqURL, err := c.resolveURL(path)
	if err != nil {
		c.audit(target, secretNames, false, err.Error())
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
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

// resolveURL turns a caller-supplied API path into an absolute URL, pinned to
// the integration's own scheme and host.
//
// Paths reach here from MCP tool arguments, i.e. from the model. Concatenating
// one onto the base URL and parsing the result afterwards is what makes that
// dangerous: "@evil.example/steal" appended to "https://api.github.com" parses
// as host evil.example with the real host demoted to userinfo, and the request
// would carry the injected Authorization header there. Parsing the path on its
// own as a relative reference removes that reading, and the final scheme/host
// comparison backstops anything else.
func (c *Client) resolveURL(path string) (string, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL %q: %w", c.baseURL, err)
	}

	ref, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("invalid request path %q: %w", path, err)
	}
	if ref.IsAbs() || ref.Host != "" || ref.User != nil {
		return "", fmt.Errorf("request path %q must be relative to %s", path, c.baseURL)
	}

	// Anchor the reference so it resolves against the base root rather than
	// relative to whatever path the base URL happens to carry.
	if !strings.HasPrefix(ref.Path, "/") {
		ref.Path = "/" + ref.Path
	}

	resolved := base.ResolveReference(ref)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return "", fmt.Errorf("refusing to send %s request to %q: the %s integration only calls %s",
			c.integrationName, resolved.Host, c.integrationName, base.Host)
	}

	return resolved.String(), nil
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
