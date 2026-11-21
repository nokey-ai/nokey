---
type: reference
title: CLI command reference
description: Every nokey CLI command, grouped by job, with its key flags and the gate it goes through (human-presence dialog, PIN, policy). Also covers the global --backend flag and NOKEY_BACKEND.
tags: [cli, commands, reference, flags]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-86b451d1f9cd856804e1756d
    resource: repo://cmd/audit.go
  - id: openwiki-source-8e87dcc3b28172929ac32c27
    resource: repo://cmd/delete.go
  - id: openwiki-source-bca3af501547eb6853c75a47
    resource: repo://cmd/export.go
  - id: openwiki-source-ac12585865802160b08976e1
    resource: repo://cmd/import.go
  - id: openwiki-source-273e7e0ce12dc59ae61d08f2
    resource: repo://cmd/keychain.go
  - id: openwiki-source-e9128ad481b0314f89a5b104
    resource: repo://cmd/policy.go
  - id: openwiki-source-3d0388561aa819a4641a4fdd
    resource: repo://cmd/proxy.go
  - id: openwiki-source-3636e2247577d19698e2906c
    resource: repo://cmd/rename.go
  - id: openwiki-source-d88dd56dbc4620bda4c35f1c
    resource: repo://cmd/root.go
  - id: openwiki-source-248790f154066b38ad98bdc1
    resource: repo://cmd/secret_gate.go
  - id: openwiki-source-b189110e3eac6b0588fc3996
    resource: repo://cmd/set.go
  - id: openwiki-source-d787e5420b7b1b0d74113e86
    resource: repo://cmd/status.go
  - id: openwiki-source-4bc42f15b878dcc5cc01031e
    resource: repo://cmd/update.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# CLI command reference

All commands live in package `cmd` (`cmd/<name>.go`) and register on `rootCmd` in `init()`. Errors exit with status 1. `nokey exec` exits with the child's code.

**Global:**

- `--backend NAME` overrides the keyring backend. It beats `NOKEY_BACKEND`, which beats `default_backend` in `config.yaml` ([Secret storage](../architecture/secret-storage.md)).
- `version [--long]` prints the version, plus the commit, build date, Go version and OS/arch with `--long`.
- `completion bash|zsh|fish|powershell` prints a shell completion script.

**The "human gate".** Several commands call `confirmHuman` (`cmd/gate.go`), which asks the *person at the machine*: the OS presence dialog where there is one, otherwise a fresh PIN. A plain y/N prompt on stdin doesn't count, because any program running nokey can answer it. See [Human presence, PIN and sessions](../security/human-presence-and-pin.md).

## Secrets

| Command | Notes |
|---|---|
| `set KEY [--stdin]` | Stores a secret, read from a hidden prompt or from stdin. The name is validated. **Replacing an existing secret** goes through the human gate (`confirmSecretChange`); a new one doesn't. |
| `list` (`ls`) `[--json]` | Lists names only, never values. Internal `__nokey_` entries are hidden. |
| `rename OLD NEW` | Human gate, because policy rules match names. The rename is copied, verified, then the old name removed. |
| `delete KEY` (`rm`, `remove`) | Human gate when the secret exists. |
| `import FILE [--dry-run]` | Imports a `.env` file. Overwriting any existing secrets goes through the human gate, listing them. |
| `export [--shell bash\|zsh\|fish\|powershell] [--only/--except]` | Prints a shell snippet that exports secrets. Human gate ("print secrets for the shell"), then PIN when one is set. Names are filtered before any value is read. |

## Running things

| Command | Notes |
|---|---|
| `exec [flags] -- CMD [ARGS]` | Injects secrets as environment variables. Flags: `--only`, `--except`, `--redact`, `--yes`, `--auth-method pin\|none` (can add a PIN, never remove one), `--isolate` (egress proxy). Enforces the approved policy and requires the human gate for `approval: always` or when there is no policy. Full flow: [Architecture overview](../architecture/overview.md#1-cli-nokey-exec----cmd), [Command execution and output redaction](../architecture/exec-and-redaction.md). |
| `mcp serve` | Starts the MCP stdio server ([MCP server](../architecture/mcp-server.md)). |
| `proxy start [--addr 127.0.0.1:0]` | Starts the header-injecting proxy in the foreground. Human gate. |
| `proxy init-ca` | Creates the local proxy CA. |
| `proxy trust-ca [--system]` | Prints instructions for trusting the CA. Details: [Secret-injecting proxy](../architecture/proxy.md). |

## Policy and config

| Command | Notes |
|---|---|
| `policy approve` | Approves `policies.yaml` exactly as it is now, storing its SHA-256 digest in the keyring. With no file, it approves running with no policy. Human gate in both cases. See [Policy file](../security/policies.md). |
| `config validate [--json]` | Strictly validates `config.yaml` and `policies.yaml`. |
| `init [--force]` | Writes starter config files. |

## Authentication

| Command | Notes |
|---|---|
| `auth setup` | Creates a PIN (Argon2id hash stored in the keyring). |
| `auth change` | Asks for the old PIN, then a new one. |
| `auth disable` | Asks for the current PIN. |
| `auth status` | Shows whether a PIN is configured. |

## Audit

| Command | Notes |
|---|---|
| `audit list` | Filters: `--since 1h\|1d\|1w\|1m`, `--secret`, `--command`, `--operation`, `--limit 20`, `--json`. |
| `audit export` | `--format json\|csv`, `--output FILE`, and the same filters. |
| `audit clear` | Asks for the PIN when one is configured or `require_auth` is set. |

See [Audit log](../security/audit-log.md).

## macOS keychain

`keychain migrate | to-dedicated | from-dedicated | backup --out FILE | restore --in FILE | prune-orphan`. See [macOS dedicated keychain and Touch ID](../architecture/macos-keychain.md).

## Diagnostics and maintenance

| Command | Notes |
|---|---|
| `status [--json] [--strict]` | Health check and config summary. `--strict` exits non-zero if any check fails. |
| `update [--check] [--force]` | Self-update, with checksums verified. Homebrew installs run `brew upgrade --cask`. See [Build, CI and release](../operations/build-test-release.md#self-update-nokey-update-internalupdate). |

Related: [Quickstart](../quickstart.md), [Configuration](configuration.md).
