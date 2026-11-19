---
type: architecture
title: MCP server
description: The nokey MCP server started by `nokey mcp serve`. Covers its seven tools, how a Handler is wired with injected dependencies, the per-call order of policy check, token/approval gateway, secret read, redacted run and audit, ${{NOKEY:NAME}} placeholders, exec options, timeouts and process-tree killing.
tags: [mcp, server, exec, placeholders, approval, tokens]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-31ea7e709d44c5057c633918
    resource: repo://cmd/mcp.go
  - id: openwiki-source-8dceeaab570f47a79d558efd
    resource: repo://internal/mcpserver/handler.go
  - id: openwiki-source-afb9f851c5b6b178ed06775c
    resource: repo://internal/mcpserver/proc_unix.go
  - id: openwiki-source-d1eb7de99d596346dd981933
    resource: repo://internal/mcpserver/proc_windows.go
  - id: openwiki-source-cae3c662916258456d23d17c
    resource: repo://internal/placeholder/placeholder.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# MCP server

`nokey mcp serve` (`cmd/mcp.go`) runs an MCP server over stdio, built on `mark3labs/mcp-go`. The server is created with:

- tool capabilities;
- **elicitation**, used for approval prompts;
- client instructions (`mcpInstructions`);
- `WithRecovery`, so a panic in one tool call does not kill the server.

All tool logic is in `internal/mcpserver/handler.go`.

## Wiring

`mcpserver.New(Deps)` builds a `Handler` from injected functions. `cmd/mcp.go` supplies:

| Dep | Provided by |
|---|---|
| `GetStore` | `getKeyring()`, which opens a keyring store per call (see [Secret storage](secret-storage.md)) |
| `GetPolicy` | `policy.Store.Current`, which hot-reloads and is digest-approved. It reads the approved digest from a fresh keyring each time, so an approval made in another terminal takes effect. `nil` means no policy. |
| `ApprovalFn` / `RememberApprovalFn` | MCP elicitation prompts (see [Approvals and session tokens](../security/approval-and-tokens.md)) |
| `AuditFn` | `recordAudit` (see [Audit log](../security/audit-log.md)) |

State the Handler keeps for the life of the server process, all in memory:

- a `token.Store` of minted tokens;
- the auto-minted session token ID;
- "don't ask again this session" **grants**, keyed by command;
- a `read` map of every secret value the server has read so far.

Every exec call's output is redacted for **all values read so far**, not just the current call's. A value read in one call can come back in a later one, for example from a file the first command wrote.

Unlike the CLI, the MCP server never prompts for the PIN. The OS keyring ACL, the policy and elicitation approvals are what gate access.

## Tools

| Tool | Purpose | Gate |
|---|---|---|
| `list_secrets` | Secret names, one per line. | None (names only). Audited. |
| `exec` | Runs a command with the selected secrets **as environment variables**. Takes `only`/`except`. | Policy, then token or approval. |
| `exec_with_secrets` | Runs a command with `${{NOKEY:NAME}}` placeholders in `args` replaced by secret values. Secrets never enter the environment. | Policy, then token or approval. |
| `mint_token` | Creates a lease for given secrets, `for` (command), `ttl_seconds` and `max_uses`. | **Always** an approval prompt. |
| `revoke_token` | Revokes a token by ID. The audit log records only a fingerprint of the ID. | None. |
| `list_tokens` | Active tokens: secrets, uses, expiry, command. | None. |
| `rename_secret` | Renames a secret. | **Always** an approval prompt, even with a token, because policy rules match secret names. |

Both exec tools refuse a call that would inject no secrets. Without a secret, nothing would gate an arbitrary command run on the agent's behalf.

## Order of checks in an exec call

`HandleExec`:

1. Reject an empty command or one containing `..`. Parse `args` (a JSON array, or a string holding one), the exec options and the timeout.
2. List secret names, **without reading values**. Reject `env` extras that share a stored secret's name (`checkEnvNotSecret`; case-insensitive on Windows). Such extras would stand in for the secret, and they aren't redacted.
3. Filter names with `env.FilterNames(only, except)`. Reject reserved secret names.
4. Take **one** policy snapshot. Run `pol.Check(command, names)`, and on denial return the denial text and write an audit entry.
5. `checkTokenOrApproval` with the same snapshot (below).
6. Read only the surviving values. Refuse any value shorter than `redact.MinRedactableLen`.
7. Call `runRedacted` with the environment `os.Environ()` + `env` extras + secrets, the later ones overriding.
8. `execOutcome` writes the audit entry and formats the result.

`HandleExecWithSecrets` differs in these ways:

- It refuses placeholders in `command`, so a secret value can't choose the binary.
- It takes secret names from `placeholder.Extract(args)`.
- It checks policy **before opening the keyring**.
- It confirms the referenced secrets exist before prompting.
- The prompt shows the args with placeholders still unresolved.
- After approval, `placeholder.Resolve` substitutes the values.
- The child's environment gets no secrets.

Placeholders match `\$\{\{NOKEY:([A-Za-z0-9_.\-]+)\}\}` (`internal/placeholder`). Extracted names are unique and sorted. Resolving fails if any referenced secret is missing.

### Token / approval gateway

`checkTokenOrApproval` runs these steps in order:

1. **An explicit `token`.** `tokenStore.UseFor(id, command, names)` either accepts the call or refuses it with a reason such as `wrong_command`.
2. **The cached auto-minted session token**, if it covers the names.
3. **`token_required` in the policy**, with no token: refuse, and tell the agent to call `mint_token`.
4. **Approval check.** With **no policy, every call that touches a secret needs approval**. Otherwise `pol.RequiresApproval` decides, and a rule resolving to `approval: never` skips prompting entirely.
5. **An existing "don't ask again" grant** for the command covering all the names.
6. **`auth.auto_mint_token`.** One prompt mints a 1-hour, unlimited-use, any-command token covering *all* stored names. Only one mint runs at a time; concurrent calls wait for it. The prompt times out after 3 minutes. If the user declines, the per-call prompt below is still required.
7. **Per-call prompt** with a "remember" option. Choosing it adds a grant.

Details of the prompts and the token store: [Approvals and session tokens](../security/approval-and-tokens.md). Policy semantics: [Policy file](../security/policies.md).

## Exec options and running

Both exec tools accept these options:

- **`cwd`**: must be absolute, an existing directory, and free of `..`. It can't be combined with a relative command path such as `./gh`, which would otherwise still match a `gh` rule.
- **`stdin`**: given as a string. Without it the child gets no stdin, because the server's own stdin is the JSON-RPC transport.
- **`env`**: non-secret extras. Names must be portable and must not be `env.Reserved`.
- **`separate_stderr`**: capture stderr on its own.

The prompt detail (`execDetail`) lists args, cwd, env and stdin, so the user sees exactly what will run.

`runRedacted` runs the command:

- **Timeout**: `timeout_seconds` defaults to 30, is capped at 300, and the result says when it was clamped.
- **Unix kill**: the child gets its own process group, and a timeout SIGKILLs the whole group (`proc_unix.go`).
- **Windows kill**: only the direct child is killed (`proc_windows.go`).
- **Backstop**: `WaitDelay` of 2s limits waiting on leftover descendants. `ErrWaitDelay` after a clean exit counts as success.
- **Output**: capped at 1 MiB (`MaxOutputBytes`), shared half and half when stderr is separate, and redacted as a whole. The cap-plus-slack scheme is described in [Command execution and output redaction](exec-and-redaction.md).

## Tests

- `internal/mcpserver/handler_test.go`: the handler.
- `cmd/mcp_server_test.go`, `cmd/mcp_integration_test.go`, `cmd/mcp_presence_test.go`: the CLI wiring and end-to-end runs.
- `internal/placeholder/placeholder_fuzz_test.go`: fuzzes placeholder parsing.

Related: [Policy file](../security/policies.md), [Approvals and session tokens](../security/approval-and-tokens.md), [Audit log](../security/audit-log.md), [Architecture overview](overview.md).
