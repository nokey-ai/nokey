# MCP Improvement Roadmap

Incremental improvements to Nokey's MCP server, ordered from quick wins to ambitious features.

| # | Improvement | Status | Complexity | Impact |
|---|------------|--------|------------|--------|
| 1 | Secret Placeholders (`exec_with_secrets`) | Done | Low | Medium |
| 2 | Scoped Policies / Per-Tool Allowlists | Done | Low-Medium | High |
| 3 | Approval Gateway / Interactive Consent | Done | Medium | High |
| 4 | Proxy Mode (HTTP/HTTPS Intercept) | Done | High | Very High |
| 5 | Pre-Built Integrations / Secret-Aware Tools | Done | High per integration | Very High |
| 6 | Time-Bounded / One-Shot Tokens | Planned | Medium | Very High |

---

## 1. Secret Placeholders (`exec_with_secrets`) — Done

Replace raw secret values with `{{NOKEY:alias}}` placeholders in tool arguments. The MCP server resolves placeholders at execution time and injects real values into the subprocess environment, so the AI agent never sees the secret in plaintext. Keeps the secret out of the conversation context entirely.

## 2. Scoped Policies / Per-Tool Allowlists — Done

Let users declare which secrets a given MCP tool is allowed to access and which commands it can run. A simple TOML/YAML policy file (e.g. `~/.nokey/policies.toml`) maps tool names to permitted secret aliases and command patterns. Prevents a compromised or misbehaving tool from requesting secrets it shouldn't have.

## 3. Approval Gateway / Interactive Consent — Done

Prompt the user for explicit approval before any secret is injected into a command. Uses MCP elicitation to pause execution and display which command is requesting which secrets. The user approves or denies via their MCP client (Claude Code, Cursor, etc.). Controlled by the `approval` field in `policies.yaml` — set globally or per-rule. Fail-closed: if the client doesn't support elicitation, the request is denied.

## 4. Proxy Mode (HTTP/HTTPS Intercept) — Done

Run a local HTTP(S) proxy that intercepts outbound API calls and injects secrets into request headers on the fly. The AI agent points its HTTP client at the proxy and never handles credentials directly. Supports any HTTP-based API without per-integration code. HTTPS interception uses a local CA cert (MITM). Configured via a `proxy:` section in `policies.yaml`. Available as `nokey proxy start` CLI command and `start_proxy`/`stop_proxy` MCP tools.

## 5. Pre-Built Integrations / Secret-Aware Tools — Done

Ship MCP tools that wrap popular services with built-in secret injection. Each integration implements an `Integration` interface and registers service-aware tools that handle authentication, policy checks, approval gating, response redaction, and audit logging automatically. The AI agent calls named tools like `github_create_issue` with structured params and never touches credentials.

The framework includes a shared API client (`internal/integration/apiclient`) that encapsulates the full security pipeline: policy check → approval → secret fetch → header injection → HTTP call → redaction → audit. New integrations implement the `Integration` interface and register via `integration.Register()`.

**GitHub integration** ships 6 tools: `github_api` (flexible, any endpoint), `github_create_issue`, `github_create_pr`, `github_list_issues`, `github_list_prs`, `github_get_file`. Uses `GITHUB_TOKEN` from the keyring with `Authorization: Bearer` header injection. Policy command: `nokey:integration:github`.

## 6. Time-Bounded / One-Shot Tokens

Issue short-lived or single-use tokens derived from stored secrets. A token expires after N seconds or after one use, whichever comes first. Limits blast radius if a token leaks during an AI session — even if intercepted, it's already dead. Requires a lightweight token-minting layer on top of the keyring.

---

## Trade-Off Summary

| Concern | Placeholders | Policies | Approval | Proxy | Integrations | Tokens |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| Secret never in context | Yes | — | — | Yes | Yes | Partial |
| Per-tool access control | — | Yes | Yes | — | Yes | — |
| User confirms each use | — | — | Yes | — | — | — |
| Works with any HTTP API | — | — | — | Yes | No | — |
| Limits leaked-token damage | — | — | — | — | — | Yes |
| Zero AI-side config | — | — | — | Yes | Yes | — |
