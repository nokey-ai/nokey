---
type: architecture
title: Architecture overview
description: How nokey is put together. Covers the single Cobra `cmd` package over `internal/*` libraries, config loading and the App context, and the end-to-end path from a stored secret to a redacted child process on the CLI (`nokey exec`), MCP (`nokey mcp serve`) and proxy routes.
tags: [architecture, overview, cli, mcp, proxy]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-7d5314d324d82f988d8fe576
    resource: repo://cmd/app.go
  - id: openwiki-source-4f2fef6805b2f3fed497f808
    resource: repo://cmd/audit_helper.go
  - id: openwiki-source-964e771d97b07ae87895d623
    resource: repo://cmd/exec.go
  - id: openwiki-source-31ea7e709d44c5057c633918
    resource: repo://cmd/mcp.go
  - id: openwiki-source-d88dd56dbc4620bda4c35f1c
    resource: repo://cmd/root.go
  - id: openwiki-source-29b4b6da030f0cb9e2e31279
    resource: repo://main.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Architecture overview

nokey keeps credentials in OS secure storage and gives them to programs, often run by an AI agent, without the agent seeing the values. It is a single Go binary.

`main.go` calls `cmd.Execute()`. All commands live in one Cobra package, `cmd/`. The libraries under `internal/` do not import `cmd`.

## Layers

```
main.go → cmd (Cobra commands, gates, wiring)
              │
              ├── internal/config    config.yaml, ConfigDir
              ├── internal/keyring   secret storage (byteness/keyring), macOS extras
              ├── internal/policy    policies.yaml, digest approval, proxy rules
              ├── internal/auth, session, presence   PIN, PIN sessions, OS auth dialog
              ├── internal/env, exec, redact, sensitive   child process + output redaction
              ├── internal/mcpserver (+ placeholder, approval, token)   MCP tools
              ├── internal/proxy     secret-injecting MITM proxy + CA
              ├── internal/audit     encrypted, HMAC-chained audit log
              └── internal/backup, update, filelock, version
```

The libraries take their collaborators as interfaces or function values, so tests and `cmd` can swap them:

- `mcpserver.Deps` holds `GetStore`, `GetPolicy`, `ApprovalFn` and `AuditFn`.
- `proxy.NewServer` takes an audit function.
- `policy.NewStore` takes a digest reader.

`cmd` declares many package-level function variables for the same purpose, such as `getKeyring`, `execRunFn`, `redactRunFn`, `osExitFn` and `keychainUnlockedFn`.

## Start-up and shared state

`cobra.OnInitialize(initConfig)` loads `config.yaml` with `config.Load()`. If loading fails, nokey prints a warning and **falls back to `config.DefaultConfig()`**. The backend can then be overridden, the `--backend` flag taking priority over the `NOKEY_BACKEND` environment variable.

`PersistentPreRun` attaches an `App{Config}` to the command context. `App.RecordAudit` writes an audit entry only when `audit.enabled` is set, and turns a write failure into a warning, never an error. A sibling helper, `recordAudit` (`cmd/audit_helper.go`), with auth method `keyring_acl`, serves the MCP server and the proxy.

`getKeyring` (`cmd/root.go`) opens a `keyring.Store` from the config: backend, service name, Touch ID, and whether to use a dedicated keychain. Commands call it whenever they need a store. See [Secret storage](secret-storage.md).

## Three ways a secret leaves the keyring

### 1. CLI: `nokey exec -- CMD`

`cmd/exec.go` runs these steps:

1. **Resolve the auth method.** A stored PIN or `require_auth` forces `pin`, and the flag can add authentication but never remove it.
2. **Load the secrets.** With a PIN, this is gated by the PIN or a valid PIN session.
3. **Filter** with `--only`/`--except`, and refuse reserved names.
4. **Load the approved policy and check it.** `token_required` rules are refused outright on the CLI, because tokens exist only inside the MCP server.
5. **Require the person at the machine** for `approval: always`, *or when there is no policy at all*. This is the OS presence dialog, or a fresh PIN where there is no dialog. Then show the y/N confirmation, unless `--yes` or `skip_confirm` is set.
6. **Run** `exec.Run` (inherited stdio) or `redact.Run` (PTY with streaming redaction). With `--isolate`, a local proxy sits in front of the child.
7. **Audit**, then exit with the child's exit code.

See [Command execution and output redaction](exec-and-redaction.md), [Human presence, PIN and sessions](../security/human-presence-and-pin.md) and [Policy file](../security/policies.md).

### 2. MCP: `nokey mcp serve`

An agent calls `exec` or `exec_with_secrets` over stdio. The handler:

1. lists names without reading values;
2. checks policy;
3. passes the token/approval gateway, which uses MCP elicitation prompts and in-memory tokens or grants;
4. reads only the approved values;
5. runs the command with a timeout;
6. returns output that has been buffered, capped and redacted.

The MCP path never prompts for the PIN. See [MCP server](mcp-server.md) and [Approvals and session tokens](../security/approval-and-tokens.md).

### 3. Proxy: `nokey proxy start` / `exec --isolate`

Here secrets never reach the child at all. A local MITM proxy adds them to request headers for hosts that match `proxy:` rules in the policy file. In isolate mode it refuses any host without a rule. See [Secret-injecting proxy](proxy.md).

## Cross-cutting controls

- **Policy** (`policies.yaml`) takes effect only once its digest has been approved by a human (`nokey policy approve`). Edits are inert until then. All three paths enforce it.
- **Audit**: every path records success or denial into the encrypted audit log when auditing is enabled. See [Audit log](../security/audit-log.md).
- **Memory**: secret maps are zeroed after use on a best-effort basis (`internal/sensitive`).
- **Trust assumption**: config files are writable by any process running as the user, so config can only *add* gates. That is why the CLI ignores `cli_enforce_policy: false` and `default_method: none` with a stored PIN. See [Threat model](../security/threat-model.md).

Related: [Quickstart](../quickstart.md), [CLI command reference](../reference/cli-commands.md), [Configuration](../reference/configuration.md).
