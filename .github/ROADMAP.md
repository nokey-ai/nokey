# MCP Improvement Roadmap

Incremental improvements to Nokey's MCP server, ordered from quick wins to ambitious features.

| # | Improvement | Status | Complexity | Impact |
|---|------------|--------|------------|--------|
| 1 | Secret Placeholders (`exec_with_secrets`) | Done | Low | Medium |
| 2 | Scoped Policies / Per-Tool Allowlists | Done | Low-Medium | High |
| 3 | Approval Gateway / Interactive Consent | Done | Medium | High |
| 4 | Proxy Mode (HTTP/HTTPS Intercept) | Planned | High | Very High |
| 5 | Pre-Built Integrations / Secret-Aware Tools | Planned | High per integration | Very High |
| 6 | Time-Bounded / One-Shot Tokens | Planned | Medium | Very High |

---

## 1. Secret Placeholders (`exec_with_secrets`) — Done

Replace raw secret values with `{{NOKEY:alias}}` placeholders in tool arguments. The MCP server resolves placeholders at execution time and injects real values into the subprocess environment, so the AI agent never sees the secret in plaintext. Keeps the secret out of the conversation context entirely.

## 2. Scoped Policies / Per-Tool Allowlists — Done

Let users declare which secrets a given MCP tool is allowed to access and which commands it can run. A simple TOML/YAML policy file (e.g. `~/.nokey/policies.toml`) maps tool names to permitted secret aliases and command patterns. Prevents a compromised or misbehaving tool from requesting secrets it shouldn't have.

## 3. Approval Gateway / Interactive Consent — Done

Prompt the user for explicit approval before any secret is injected into a command. Uses MCP elicitation to pause execution and display which command is requesting which secrets. The user approves or denies via their MCP client (Claude Code, Cursor, etc.). Controlled by the `approval` field in `policies.yaml` — set globally or per-rule. Fail-closed: if the client doesn't support elicitation, the request is denied.

## 4. Proxy Mode (HTTP/HTTPS Intercept)

Run a local HTTP(S) proxy that intercepts outbound API calls and injects secrets into request headers or bodies on the fly. The AI agent points its HTTP client at the proxy and never handles credentials directly. Supports any HTTP-based API without per-integration code, though HTTPS interception requires a local CA cert.

## 5. Pre-Built Integrations / Secret-Aware Tools

Ship MCP tools that wrap popular services (GitHub, AWS, Stripe, etc.) with built-in secret injection. Each integration knows which headers or environment variables a service expects and handles the wiring automatically. High effort per integration, but delivers the smoothest developer experience for supported services.

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
