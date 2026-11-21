---
type: quickstart
title: nokey quickstart
description: Orientation for the nokey repository. Covers what nokey does, its three ways of handing out secrets (CLI exec, MCP server, proxy), how to build, test and run it, the repository layout, and a map from common tasks to the wiki page and source files to read.
tags: [quickstart, overview, navigation, build]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-d88dd56dbc4620bda4c35f1c
    resource: repo://cmd/root.go
  - id: openwiki-source-29b4b6da030f0cb9e2e31279
    resource: repo://main.go
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
  - id: openwiki-source-23775c3de52f3ab95a13cb8b
    resource: repo://README.md
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# nokey quickstart

**nokey** is a single Go binary (`github.com/nokey-ai/nokey`) that keeps credentials in the OS keyring and hands them to commands, usually commands an AI coding assistant runs, **without the assistant seeing the values**. It runs on macOS, Linux and Windows (amd64 and arm64).

A secret reaches a program in one of three ways:

1. **`nokey exec -- CMD`**: injected as environment variables, optionally with PTY output redaction.
2. **`nokey mcp serve`**: an MCP stdio server whose `exec` and `exec_with_secrets` tools run commands for an agent, behind policy and human approval.
3. **`nokey proxy start` / `exec --isolate`**: a local MITM proxy adds secrets to HTTPS request headers, so the child never holds them.

Every route passes through the same controls:

- an approved `policies.yaml`;
- human-only confirmation (the macOS presence dialog or a PIN);
- redaction;
- an optional encrypted audit log.

Start with [Architecture overview](architecture/overview.md).

## Build, test, run

```bash
make build        # ./nokey (ad-hoc codesigned on macOS for keychain/Touch ID)
make test         # go test ./...
make check        # test + vet + golangci-lint — local equivalent of CI
go test ./... -race   # what CI runs on Linux and macOS

./nokey init                  # starter config.yaml and policies.yaml
./nokey set OPENAI_API_KEY    # prompted, no echo
./nokey exec --only OPENAI_API_KEY -- some-command
./nokey mcp serve             # MCP stdio server for an AI client
```

Users install with `brew install nokey-ai/tap/nokey` or `go install github.com/nokey-ai/nokey@latest`. Releases are tag-driven through GoReleaser. See [Build, CI and release](operations/build-test-release.md).

## Layout

| Path | What |
|---|---|
| `main.go` | calls `cmd.Execute()` |
| `cmd/` | all Cobra commands, the human gate (`gate.go`, `secret_gate.go`), MCP and proxy wiring |
| `internal/keyring` | keyring wrapper, name rules, macOS dedicated keychain and build trust |
| `internal/policy` | `policies.yaml`: rules, digest approval, hot-reload store, proxy rules |
| `internal/mcpserver`, `placeholder`, `approval`, `token` | MCP tools, `${{NOKEY:NAME}}`, elicitation prompts, leases |
| `internal/env`, `exec`, `redact`, `sensitive` | child environment, process runners, redaction, memory zeroing |
| `internal/proxy` | header-injecting proxy and local CA |
| `internal/auth`, `session`, `presence` | PIN, PIN session tickets, OS presence dialog |
| `internal/audit`, `backup`, `config`, `update`, `filelock`, `version` | audit log, sealed backups, config, self-update, support |
| `examples/policies.yaml` | annotated policy example |
| `.github/workflows/`, `.goreleaser.yaml`, `Makefile` | CI, release, build |

## Where to go for a task

| If you need to… | Read | Start in |
|---|---|---|
| Understand the end-to-end flow | [Architecture overview](architecture/overview.md) | `cmd/app.go`, `cmd/root.go`, `cmd/exec.go` |
| Change how secrets are stored, named or listed | [Secret storage](architecture/secret-storage.md) | `internal/keyring/keyring.go` |
| Work on macOS keychain, Touch ID, migration or backups | [macOS dedicated keychain](architecture/macos-keychain.md) | `internal/keyring/*_darwin.go`, `cmd/keychain.go`, `internal/backup` |
| Change env injection, reserved names or redaction | [Command execution and output redaction](architecture/exec-and-redaction.md) | `internal/env`, `internal/redact` |
| Add or change an MCP tool | [MCP server](architecture/mcp-server.md) | `internal/mcpserver/handler.go`, `cmd/mcp.go` |
| Change proxy injection or the CA | [Secret-injecting proxy](architecture/proxy.md) | `internal/proxy`, `cmd/proxy.go` |
| Change policy semantics or approval of edits | [Policy file](security/policies.md) | `internal/policy`, `cmd/policy.go` |
| Change MCP prompts, grants or tokens | [Approvals and session tokens](security/approval-and-tokens.md) | `cmd/gate.go`, `internal/approval`, `internal/token` |
| Change PIN, sessions or the presence dialog | [Human presence, PIN and sessions](security/human-presence-and-pin.md) | `internal/auth`, `internal/session`, `internal/presence` |
| Change auditing | [Audit log](security/audit-log.md) | `internal/audit` |
| Judge the security impact of a change | [Threat model](security/threat-model.md) | `README.md` § Threat Model, `SECURITY.md` |
| Look up a command or flag | [CLI command reference](reference/cli-commands.md) | `cmd/*.go` |
| Look up a config key or on-disk file | [Configuration](reference/configuration.md) | `internal/config/config.go` |
| Write or fix tests | [Testing](operations/testing.md) | `cmd/main_test.go`, `cmd/helpers_test.go` |
| Ship a release | [Build, CI and release](operations/build-test-release.md) | `.github/workflows/release.yml`, `.goreleaser.yaml` |

## Invariants to keep

These hold everywhere. Check every change against them:

- **Human approval comes only from the OS presence dialog or a fresh PIN.** A stdin prompt never counts, and neither does an MCP client's Accept on its own.
- **Files can only add gates.** Anything that loosens a gate (an approved policy, the PIN) is anchored in the keyring.
- **Policy before values.** Filter names, check policy and approve *before* reading secret values.
- **Fail closed.** No matching rule means approval is required. No policy means a human is asked. No elicitation or presence support means denial.
- **Names, never values,** go into prompts, logs, audit entries and errors.

Related: [Architecture overview](architecture/overview.md), [CLI command reference](reference/cli-commands.md), [MCP server](architecture/mcp-server.md).
