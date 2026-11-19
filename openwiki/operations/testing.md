---
type: testing
title: Testing
description: How nokey's tests are laid out and kept hermetic. Covers the cmd package's TestMain stubs for the keyring and presence dialog, the in-memory keyring and helper functions, function-variable seams, MCP JSON-RPC integration tests, fuzz targets, platform-tagged tests, and the lint rules.
tags: [testing, fuzzing, lint, ci, seams]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-3bea3530072bb2f5acdc3c30
    resource: repo://.golangci.yml
  - id: openwiki-source-d1d9789eb35e7f14ebd23458
    resource: repo://cmd/helpers_test.go
  - id: openwiki-source-7cd85779aa7e6d8646668480
    resource: repo://cmd/main_test.go
  - id: openwiki-source-d9030070b5f4181413c9c9fa
    resource: repo://cmd/mcp_integration_test.go
  - id: openwiki-source-dd2503bf471e86b6c4542300
    resource: repo://internal/backup/backup_fuzz_test.go
  - id: openwiki-source-f37cbcf09cb209e931074c4c
    resource: repo://internal/keyring/buildtrust_darwin_test.go
  - id: openwiki-source-ac1afc23925ae59919b2f8be
    resource: repo://internal/keyring/keyring.go
  - id: openwiki-source-4330e6213b9a026e6791bf99
    resource: repo://internal/placeholder/placeholder_fuzz_test.go
  - id: openwiki-source-a72965ffce57cc6d6f2a59e9
    resource: repo://internal/policy/policy_fuzz_test.go
  - id: openwiki-source-41962005d74da2005648a5f6
    resource: repo://internal/proxy/rules_fuzz_test.go
  - id: openwiki-source-935f27b3c0c2015e39be8c27
    resource: repo://internal/proxy/server_fuzz_test.go
  - id: openwiki-source-c9fec24ed85d3260b3b2c974
    resource: repo://internal/redact/redact_unix_test.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Testing

Tests sit next to the code as `_test.go` files: roughly 59 files and twice as many lines as the production code. Run them with `make test` (`go test ./...`), or `make check` to add vet and golangci-lint. CI also runs `-race` on Linux and macOS and a `GOOS=windows go vet` ([Build, CI and release](build-test-release.md)).

## Keeping tests away from the real keychain

A test that reaches the real macOS Keychain can hang until a timeout while it waits for a UI dialog nobody can answer. `cmd/main_test.go` prevents this. Its `TestMain` replaces two package variables before any test runs:

- `getKeyring` returns an error ("no keyring installed").
- `presenceConfirmFn` reports `presence.ErrUnavailable`, so no test ever shows a Touch ID dialog.

Tests opt back in with helpers from `cmd/helpers_test.go` and `main_test.go`:

| Helper | Purpose |
|---|---|
| `newTestStore()` / `mockRing` | A `keyring.Store` over an in-memory ring (`keyring.NewWithRing`). |
| `withTestKeyring(t, store)` | Installs that store as `getKeyring` for the test. |
| `withPresence(t, err)` | Stands in for the person at the machine and records each prompt reason. |
| `withTestConfig`, `withTestAuditDir`, `withStdin`, `captureStdout`/`captureStderr` | Global config, audit directory, stdin and output capture. |
| `withExecGlobals` | Resets exec flag globals. |
| `approveTestPolicy`, `approveTestPolicyIn`, `withProxyPolicy` | Write a policy and store its approved digest, as `nokey policy approve` would. |

Each helper restores the original through `t.Cleanup`.

## Seams

Production code exposes package-level function variables so tests can swap them out:

- `cmd`: `execRunFn`, `redactRunFn`, `osExitFn`, `keychainUnlockedFn`, `applyKeychainSettingsFn`, `findStaleTouchIDItemFn`, `openKeyringForFn`, `promptPasswordFn` and `readPasswordStdinFn`.
- `internal/redact`: `ptyStartFn` and `ptyInheritSizeFn`.
- `internal/mcpserver`: `autoMintPromptTimeout` and `envNamesFoldCase`.
- Libraries take dependencies as values:
  - `mcpserver.Deps`;
  - `proxy.NewServer(..., auditFn)` and `Server.SetTransport`;
  - `policy.NewStore(dir, digestFn)`;
  - `proxy.KeyStore`.

## MCP integration

`cmd/mcp_integration_test.go` drives a real `mcp-go` server over JSON-RPC pipes:

1. initialize;
2. `tools/list`;
3. `tools/call`.

It uses the same `mcpserver.New` wiring as `nokey mcp serve`. `cmd/mcp_presence_test.go` and `cmd/mcp_server_test.go` cover approval behaviour. `internal/mcpserver/handler_test.go` unit-tests the handler with fake stores and approval functions.

## Fuzzing

| Target | File |
|---|---|
| `FuzzLoad` (policy parsing and validation) | `internal/policy/policy_fuzz_test.go` |
| `FuzzExtract` (placeholders) | `internal/placeholder/placeholder_fuzz_test.go` |
| `FuzzDecrypt` (sealed backups) | `internal/backup/backup_fuzz_test.go` |
| `FuzzResolveTemplateMatchesPolicy` (proxy header templates vs policy refs) | `internal/proxy/rules_fuzz_test.go` |
| `FuzzValidateListenAddr` (loopback check) | `internal/proxy/server_fuzz_test.go` |

`go test` runs only the seed corpus. Run a single target with `go test -fuzz=FuzzLoad ./internal/policy`.

## Platform-specific tests

- `//go:build darwin`: `internal/keyring/buildtrust_darwin_test.go`, `keychain_settings_darwin_test.go` and `keychain_status_darwin_test.go`. These create throwaway keychains, for example with service `nokey-test`, and run only on macOS: locally or on the macOS CI job.
- `internal/redact/redact_unix_test.go` (`!windows`) exercises the PTY runner.
- Windows code has no runtime tests in CI. It is only type-checked by the cross-OS vet.

## Lint (`.golangci.yml`)

golangci-lint v2 runs these linters:

- errcheck, govet, staticcheck, unused, gosec;
- errorlint, noctx, bodyclose, contextcheck;
- misspell, nolintlint (with `require-specific`), copyloopvar, unconvert.

The formatters are gofmt and goimports.

Exclusions, each with a reason in the file:

- gosec G204 (subprocesses with variable arguments are the tool's purpose);
- G304 (it reads user-specified files);
- G115 (terminal `Fd()` conversions);
- G103 inside `internal/sensitive` (deliberate `unsafe` for zeroing);
- errcheck, gosec and noctx in test files.

Related: [Build, CI and release](build-test-release.md).
