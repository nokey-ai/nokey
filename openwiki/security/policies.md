---
type: security
title: Policy file
description: The semantics of policies.yaml. Covers rules mapping command patterns to secret patterns, approval modes and token_required, how commands are identified (bare name versus absolute path), how a missing policy differs from a policy with rules, digest-based approval through `nokey policy approve`, and hot reload in the MCP server.
tags: [security, policy, approval, rules, digest]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-964e771d97b07ae87895d623
    resource: repo://cmd/exec.go
  - id: openwiki-source-31ea7e709d44c5057c633918
    resource: repo://cmd/mcp.go
  - id: openwiki-source-e9128ad481b0314f89a5b104
    resource: repo://cmd/policy.go
  - id: openwiki-source-8dceeaab570f47a79d558efd
    resource: repo://internal/mcpserver/handler.go
  - id: openwiki-source-182018713d640f72e4f6c64f
    resource: repo://internal/policy/policy.go
  - id: openwiki-source-f2de8c67e6c7d35204796bf4
    resource: repo://internal/policy/store.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Policy file

`<ConfigDir>/policies.yaml` says **which commands may receive which secrets**, whether a human must approve each use, whether a token is required, and which hosts the proxy injects headers for. The code is in `internal/policy` (`policy.go`, `store.go`, `proxy.go`) and `cmd/policy.go`. An annotated example is in `examples/policies.yaml`.

```yaml
approval: always            # global default for rules that don't set one
rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
    approval: never         # no prompt for this pair
  - commands: ["/usr/local/bin/terraform"]
    secrets: ["AWS_*"]
    token_required: true    # MCP only: needs a minted token
proxy:
  rules:
    - hosts: ["api.openai.com"]
      headers: { Authorization: "Bearer $OPENAI_API_KEY" }
```

Validation:

- Every rule needs non-empty `commands` and `secrets`.
- `approval` must be `always`, `never` or omitted.
- Proxy rules have their own checks ([Secret-injecting proxy](../architecture/proxy.md#rules-in-policiesyaml)).
- Bad files are rejected when loaded.
- `nokey config validate` and `policy approve` parse strictly and reject unknown keys.

## Evaluation

All three run per secret against `policy.CommandKey(command)`, and the **first matching rule** wins.

| Question | No policy (`nil`) | No matching rule | Matching rule |
|---|---|---|---|
| `Check`: is it allowed? | allowed | **denied** (`Denial`) | allowed |
| `RequiresApproval` | false at the policy level (but see below) | **true**, which fails closed | `rule.approval`, else the global `approval`. Only `always` means yes. |
| `RequiresToken` | false | false | `rule.token_required` |

A call asking for no secrets is always allowed.

**No policy still means asking a human.** Both the CLI and the MCP server treat a `nil` policy, while secrets are involved, as **needing human approval**. Without that, deleting the policy or its digest would remove every gate:

- `nokey exec` requires `confirmHuman`.
- The MCP server prompts for every access.

So "no policy" means *allowed if the human approves*, and a policy with rules means *deny by default*.

**Denials** carry a hint for the agent. The hint names the rule to add and says to run `nokey policy approve` in a terminal.

### How commands are matched

`CommandKey` leaves a bare name such as `gh` as is. A path is made absolute and cleaned, and **never reduced to its last element**, so `/tmp/evil/gh` is not `gh`.

`MatchCommand(pattern, key)`:

- `*` matches every command.
- Otherwise, a pattern **without** a path separator matches only bare names, which resolve through the nokey process's PATH. A pattern **with** a separator matches only paths.
- Matching uses `path.Match` globbing.

Secret patterns are globs too. Malformed patterns match nothing. Tokens and "don't ask again" grants use the same `CommandKey` and `MatchCommand` ([Approvals and session tokens](approval-and-tokens.md)).

### Where it's enforced

| Path | Check | `token_required` | Approval |
|---|---|---|---|
| `nokey exec` | yes | refused outright: tokens exist only in MCP | `confirmHuman` for `always` or no policy |
| MCP `exec`, `exec_with_secrets` | yes, before any value is read | must present a token | elicitation, then presence ([MCP server](../architecture/mcp-server.md)) |
| proxy | rules come from the policy | — | `always` not allowed; `proxy start` itself asks for human confirmation |

## Digest approval

`policies.yaml` is a file any process running as the user can rewrite. **Edits therefore take no effect until a human approves them.**

- `nokey policy approve`:
  1. parses the file strictly;
  2. prints it with its SHA-256;
  3. asks for `confirmHuman` ("approve policies.yaml (sha256 …)");
  4. stores the digest in the keyring under `__nokey_policy_digest__`;
  5. writes the audit entry `policy:approve`.
- With no file but a digest still stored, it asks the human to approve running **without** a policy, then deletes the digest.
- `LoadApproved(dir, digest)` applies the file only if its digest matches. Otherwise it returns `NotApprovedError`. There are two cases:
  - **edited or never approved**: the file exists but its digest doesn't match;
  - **removed**: the file is gone while a digest is still stored.

What each caller does when the file isn't approved:

- **CLI** (`loadApprovedPolicy`): `exec` and `proxy start` fail with "failed to load policy: … run 'nokey policy approve'".
- **MCP** (`policy.Store`):
  - At startup an unapproved file isn't fatal. The server warns and runs with **no policy**, so every access prompts.
  - On each request `Current()` stats the file and reloads it when the mtime, size or existence changes, or while a file is waiting for approval. The approved digest is read from a fresh keyring each time, so an approval made in another terminal takes effect at once.
  - A reload that fails (malformed or unapproved) **keeps the previously applied policy** and warns once.
  - `Get` is lock-free (`atomic.Pointer`).

## Tests

- `internal/policy/policy_test.go`: evaluation and command keys.
- `store_test.go`: reload, pending approval and keep-previous.
- `proxy_test.go`: proxy rules.
- `policy_fuzz_test.go`: fuzzes `Load`.
- `cmd/policy_test.go`: the approve flow.

Related: [Approvals and session tokens](approval-and-tokens.md), [MCP server](../architecture/mcp-server.md), [Secret-injecting proxy](../architecture/proxy.md), [Threat model](threat-model.md).
