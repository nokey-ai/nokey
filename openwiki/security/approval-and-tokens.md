---
type: security
title: Approvals and session tokens
description: How the MCP server gets a human's consent. An elicitation prompt goes to the MCP client, followed by the OS presence dialog the agent can't answer. Covers prompt construction that resists forged lines, "don't ask again" grants, and the in-memory token (lease) store with minting limits, scope matching, use counting and revocation.
tags: [security, approval, elicitation, tokens, mcp, presence]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-3ee2d664d6dbd59a209da7a0
    resource: repo://cmd/gate.go
  - id: openwiki-source-9e2652ca653f54e22ed68bcc
    resource: repo://internal/approval/approval.go
  - id: openwiki-source-8dceeaab570f47a79d558efd
    resource: repo://internal/mcpserver/handler.go
  - id: openwiki-source-e12af55390a7e6e951fd052b
    resource: repo://internal/presence/presence_darwin.go
  - id: openwiki-source-8865edae259f173d342c88f5
    resource: repo://internal/presence/presence_other.go
  - id: openwiki-source-20e362a297b9d4acbb99c7a4
    resource: repo://internal/presence/presence.go
  - id: openwiki-source-f7e64319b47b7813318d5af5
    resource: repo://internal/token/store.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Approvals and session tokens

When an MCP call needs consent ([MCP server → gateway](../architecture/mcp-server.md#token--approval-gateway)), nokey asks for it in **two steps**. A **token** can then stand in for repeated approvals.

## Two-step approval

`cmd/gate.go` wraps the elicitation prompts from `internal/approval` before passing them to the MCP server:

```
mcpApprovalFn         = presenceApproval(approval.RequestWithDetail)
mcpRememberApprovalFn = presenceRememberApproval(approval.RequestRememberable)
```

1. **Elicitation.** An MCP `elicitation/create` request goes to the client: "nokey: "CMD" wants to access secret(s): …", followed by a detail block, with Accept and Decline. **Accept** is the approval. **Decline** and **Cancel** deny, and so does anything else.
   - The prompt **fails closed**. If the client doesn't support elicitation, or there's no active session, access is denied.
2. **Presence dialog.** The MCP client may be the very agent asking for the secret, so its Accept only lets the request *reach* the person at the machine. The OS presence dialog (`internal/presence`, the macOS LocalAuthentication dialog) must then pass, with text that repeats the command, a short version of the detail, and the secret names.
   - The MCP server has no terminal, so **there is no PIN fallback**. Where no presence dialog is available, approval fails.

`presenceReason` builds the dialog text:

- The command, the detail (capped at 200 bytes) and any "for the rest of this session…" note come *before* the secret names. If the dialog cuts text, it is the long part that gets cut, never the scope.
- A "remember" choice comes from the client, so it is returned only *after* the dialog, which states it, has passed. A grant can neither skip the dialog nor ride on one that didn't mention it.

### Prompt text can't be forged

Values the model controls are rendered with Go `%q` quoting, so a newline or control character can't forge a line in the prompt:

| Helper | Shows | Cap |
|---|---|---|
| `Quote` | one value | 256 bytes |
| `FormatArgs` | the arguments | 512 bytes, plus a note of how much was cut |
| `FormatEnv` | the environment variables | 512 bytes, plus a note of how much was cut |
| `FormatStdin` | stdin's size and a preview | 64-byte preview |

Arguments are shown **before** placeholders are resolved, so the prompt never contains a secret value but does show where each one goes. The prompt detail (`execDetail`) lists args, cwd, env and stdin. The user approves exactly what will run, not just a command name.

## "Don't ask again this session" grants

`RequestRememberable` adds a `remember` checkbox: "Approve CMD with these secrets (or fewer) without prompting until this MCP session ends".

When ticked and approved, the handler records a grant under `policy.CommandKey(command)` → set of secret names. A later call with the same command key and a **subset** of those names skips the prompt (`granted`). Grants for one command accumulate and live only in memory, so they end with the server process.

A grant replaces *only the prompt*. The policy check, `token_required`, and `approval: never` are all applied before the grant is consulted.

## Tokens (`internal/token`)

A token is a lease: a 64-hex-character random ID (32 bytes from `crypto/rand`) that authorizes:

- a set of **secrets**;
- for a **command pattern** (`MintedFor`, default `*`);
- until **ExpiresAt**;
- for **MaxUses** uses (0 means unlimited until expiry).

The `token.Store` is **in memory and per process**. Tokens die when `nokey mcp serve` exits.

**Minting** (`mint_token` tool):

- `MintRequest.Validate` requires at least one secret, `ttl_seconds` between 1 and **3600**, non-negative `max_uses`, and a valid glob for `for`. It runs *before* the user is prompted, so they're never asked to approve a token that can't be created.
- The secrets must exist.
- Minting **always** needs approval (the two-step flow above). The detail shows `for`, ttl and max_uses.

**Using a token** (the `token` parameter on exec tools): `UseFor(id, command, secrets)` checks, in order:

| Check | Refusal reason |
|---|---|
| The token exists | `not_found` |
| It hasn't expired | `expired` |
| It has uses left | `exhausted` |
| It covers **every** requested secret | `wrong_secret` |
| `MintedFor` matches the command, using the same matching as policy rules (`policy.MatchCommand` against `policy.CommandKey(command)`) | `wrong_command` |

On success it uses up one use, and removes the token once its uses run out. Expired tokens are cleaned up on mint and list.

**Revoke and list.** `revoke_token` deletes a token; the audit log records only a fingerprint of the ID, because a live ID works as a bearer credential. `list_tokens` shows each token's secrets, uses, expiry and command.

**Policy `token_required`.** A rule can demand a token. Without one, the call is refused with instructions to mint. The CLI refuses such rules outright, because tokens exist only inside the MCP server ([Policy file](policies.md)).

**Auto-mint** (`auth.auto_mint_token: true`). On the first call that needs approval, one prompt mints a session token: all stored secrets, 1 hour, unlimited uses, any command. Later calls skip prompting while it's valid. If the user declines, the per-call prompt is still required.

## Tests

- `internal/approval/approval_test.go`: actions, fail-closed behaviour, quoting and caps.
- `internal/token/store_test.go`: the token store, using an injectable clock.
- `cmd/mcp_presence_test.go`: the presence step after elicitation.
- `internal/mcpserver/handler_test.go`: grants and auto-mint concurrency.

Related: [MCP server](../architecture/mcp-server.md), [Human presence, PIN and sessions](human-presence-and-pin.md), [Policy file](policies.md).
