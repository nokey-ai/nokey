---
type: architecture
title: Command execution and output redaction
description: How nokey builds a child process environment from stored secrets (only/except filtering, reserved variable names), runs the child with signal forwarding, and redacts secret values and their encodings from its output, both streaming (CLI) and buffered (MCP).
tags: [exec, redaction, environment, security, cli, mcp]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-964e771d97b07ae87895d623
    resource: repo://cmd/exec.go
  - id: openwiki-source-a8910515ddd14810ad43f5c1
    resource: repo://internal/config/config.go
  - id: openwiki-source-1b85e4a049ce8709a644dc00
    resource: repo://internal/env/env.go
  - id: openwiki-source-3abd39b3bafcbad2b1ffa331
    resource: repo://internal/env/filter.go
  - id: openwiki-source-34849cd14a21981beb8df30c
    resource: repo://internal/env/reserved.go
  - id: openwiki-source-35edb9e34a9df7610ef9ebb0
    resource: repo://internal/exec/exec.go
  - id: openwiki-source-8dceeaab570f47a79d558efd
    resource: repo://internal/mcpserver/handler.go
  - id: openwiki-source-695ee204322a5d60a2359ad4
    resource: repo://internal/redact/redact_unix.go
  - id: openwiki-source-2be3822dd7d14adf15909677
    resource: repo://internal/redact/redact_windows.go
  - id: openwiki-source-1b12bdfadc53a77fea7a7fec
    resource: repo://internal/redact/redact.go
  - id: openwiki-source-d3fd22a0e56438f2a7ed54aa
    resource: repo://internal/sensitive/clear.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Command execution and output redaction

nokey hands secrets to a program as environment variables. Running a command takes three steps:

1. Choose the secrets and check their names (`internal/env`).
2. Start the child with those secrets merged into its environment, either directly (`internal/exec`) or behind a redactor (`internal/redact`).
3. Wipe what memory can be reached afterwards (`internal/sensitive`).

The CLI `nokey exec` and the MCP `exec` / `exec_with_secrets` tools share the env and redaction code. Each has its own process runner.

## Choosing secrets: only / except

`env.FilterSecrets` filters a map of loaded values. `env.FilterNames` applies the same rules to a list of names before any value is read. Both refuse `only` and `except` together. With `only`, a name that doesn't exist is an error rather than being silently dropped. With `except`, every other secret is kept. Names are comma-separated and trimmed (`ParseCommaSeparated`).

- The CLI (`cmd/exec.go`) loads every secret (through the PIN gate when one applies) and then calls `FilterSecrets`.
- The MCP server calls `FilterNames` first. That way it reads from the keyring only the values it will inject (`internal/mcpserver/handler.go`, around line 486).
- `nokey export` uses `FilterNames` the same way.

## Reserved variable names

`internal/env/reserved.go` lists variables a caller may not set in a child's environment. These are variables that make a program load other code, read its configuration from somewhere else, or send its traffic somewhere else:

- `PATH`, `BASH_ENV`, `IFS`, `PROMPT_COMMAND`
- `NODE_OPTIONS`, `GIT_ASKPASS`
- `XDG_CONFIG_HOME`, `CURL_HOME`
- `HTTP(S)_PROXY`, `NO_PROXY`
- `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and others

It also blocks whole prefixes: `LD_`, `DYLD_`, `PYTHON`, `RUBY`, `GIT_SSH`, `GIT_CONFIG`, `NPM_CONFIG_`, `CARGO_` and others. Matching ignores case because Windows variable names ignore case.

There are two checks:

- `Reserved(name)` applies to environment variables a caller passes directly. The MCP server rejects such a name (handler.go, around line 1060).
- `ReservedSecretName(name)` applies to stored secret names, because each secret becomes an environment variable. It exempts names that end in a credential suffix (`_TOKEN`, `_KEY`, `_SECRET`, `_PASSWORD`, `_AUTH`). So `CARGO_REGISTRY_TOKEN` is allowed even though `CARGO_` is a reserved prefix.

Both the CLI and the MCP path refuse to run when a selected secret has a reserved name.

## Merging the environment

`env.MergeEnvironment(current, secrets)` copies the parent environment, drops any variable a secret overrides, then appends the secrets. **Secrets take precedence** over inherited variables of the same name. Both runners append `extraEnv` (proxy variables from `--isolate`) after the merge, so those win over everything.

## Running without redaction: `internal/exec`

`exec.Run` starts the command with inherited stdin, stdout and stderr. It forwards SIGINT and SIGTERM to the child only after a successful start, and returns the child's exit code. Failing to start the command returns exit code 1 and an error. `cmd/exec.go` then exits with the child's code. It stops the isolation proxy and calls `sensitive.ClearMap` on the secrets first, because `os.Exit` skips deferred calls.

## Running with redaction: `internal/redact`

Redaction is used when you pass `--redact`, or when config sets `redact_by_default` and the flag isn't given explicitly.

**Unix (`redact_unix.go`, `!windows`).** The child runs on a PTY (`creack/pty`). Behaviour:

- stdin switches to raw mode when it is a terminal.
- SIGWINCH resizes the PTY.
- SIGINT and SIGTERM are forwarded to the child.
- PTY output passes through a streaming `redactingReader` before reaching stdout.

stdout and stderr share the PTY, so both are redacted. The goroutine copying stdin to the PTY is deliberately left running after `Run` returns: it is blocked in `Read`. That is only acceptable because `Run` is for the CLI, whose process exits right after.

**Windows (`redact_windows.go`).** There is no PTY. stdout and stderr are separate pipes, each with its own `redactingReader` sharing one redactor. Only `os.Interrupt` is forwarded.

### What is matched

`newRedactor` maps every secret value to `[REDACTED:NAME]`. For values of at least `MinRedactableLen` (4) bytes it also adds encoded forms:

- the reversed bytes;
- standard and URL base64, padded and unpadded;
- URL query and path escaping;
- JSON string escaping, with and without HTML escaping;
- lowercase and uppercase hex.

Secrets of at least 8 bytes also get "offset base64 middles". These are the parts of the base64 encoding that depend only on the secret when it starts 0, 1 or 2 bytes into a base64 group, so a password inside an encoded `user:pass` Basic-auth header is still caught.

Matching is deterministic:

- Each secret's literal value gets its own name as label first, so it wins over any other secret's encoding.
- Names are processed in sorted order.
- Patterns are applied longest first, with ties broken by the pattern itself.

### Streaming across reads

A secret can be split across two reads. `redactingReader` holds back any tail that could still grow into a match (`pendingLen`) and releases it only once the next read confirms or rules it out. `safeSplit` also moves the cut back past any complete match that crosses it, so a shorter overlapping pattern cannot win on one side. Streaming output is therefore identical to redacting the whole stream at once.

The exception is periodic secrets (such as `aaaaaaaa...`), whose overlapping matches can chain without end. There the retreat stops at `2*maxLen` and `boundedSplit` picks the cut. With several overlapping periodic secrets, fragments may then escape. When nothing could start a match, `pendingLen` returns 0, so prompts without a trailing newline aren't delayed.

### Buffered redaction in MCP

The MCP tools don't stream. They capture output into a `cappedBuffer` and call `redact.RedactBytes` on it (handler.go, `capOutput`). The buffer keeps `6*longest+4` bytes of slack past the output cap, so a secret crossing the cap is still whole when redacted. If the output overflowed, that slack is dropped before the truncation notice is added. A fragment of a secret cut by the cap therefore cannot leak.

The MCP server also refuses to inject any secret shorter than `MinRedactableLen`, since output redaction is what hides values from the agent.

## Memory hygiene

`internal/sensitive` zeros secret values on a best-effort basis:

- `ClearMap` and `ClearBytes` cover maps and byte slices.
- String clearing goes through `unsafe`.
- The redactor's `Clear` zeros its patterns.
- `redactingReader.Clear` zeros the held tail and buffers.

The package documents its limits:

- Copies made at `execve`, `fmt.Sprintf` intermediates and copies inside libraries are out of reach.
- Freed pages aren't zeroed.
- Strings under 8 bytes are skipped, so Go's interned strings aren't corrupted.

See [Threat model](../security/threat-model.md) for what this does and does not protect.

## Tests

- `internal/redact/redact_test.go`: variants, determinism, split matches across reads, periodic secrets. One test there, `TestEncodingVariants_Base64MiddlesAreLongEnough`, checks the minimum length of base64 middles.
- `redact_unix_test.go`: PTY runs, with `ptyStartFn` and `ptyInheritSizeFn` swapped out.
- `internal/env/*_test.go`: filtering and reserved names.
- `cmd/exec_test.go`: CLI flow, using the injectable `execRunFn`, `redactRunFn` and `osExitFn`.

Related: [MCP server](mcp-server.md), [Threat model](../security/threat-model.md), [Policy file](../security/policies.md).
