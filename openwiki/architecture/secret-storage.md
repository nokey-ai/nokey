---
type: architecture
title: Secret storage and keyring backends
description: How nokey stores secrets through its keyring.Store wrapper over byteness/keyring. Covers backend selection per OS and via --backend/NOKEY_BACKEND, secret-name validation and the reserved __nokey_ namespace for nokey's own state, caching, the verified rename, and migration of the encrypted file backend's directory.
tags: [keyring, storage, backends, secrets, validation]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-d88dd56dbc4620bda4c35f1c
    resource: repo://cmd/root.go
  - id: openwiki-source-f42f58941c9d73aeae96953f
    resource: repo://internal/audit/audit.go
  - id: openwiki-source-b12cba1b5936a1da8739d39c
    resource: repo://internal/auth/auth.go
  - id: openwiki-source-a8910515ddd14810ad43f5c1
    resource: repo://internal/config/config.go
  - id: openwiki-source-ac1afc23925ae59919b2f8be
    resource: repo://internal/keyring/keyring.go
  - id: openwiki-source-fd56d3d8ab88a5981d331175
    resource: repo://internal/keyring/migrate_filedir.go
  - id: openwiki-source-182018713d640f72e4f6c64f
    resource: repo://internal/policy/policy.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Secret storage and keyring backends

Every secret nokey holds, and all of its own sensitive state, lives in an OS keyring that `internal/keyring` accesses. `keyring.Store` wraps `github.com/byteness/keyring`, a fork that adds Touch ID. Commands get a store from `getKeyring()` in `cmd/root.go`.

## Backends

`keyring.New(backend, serviceName, useBiometrics, dedicated, keychainName)`:

- The service name defaults to `nokey`.
- An **empty backend** allows every backend the library supports and lets it pick the platform default.
- A named backend restricts the library to that one.

| Backend | Platform |
|---|---|
| *(empty)* | system default (recommended) |
| `keychain` | macOS Keychain (login keychain, or a dedicated file; see [macOS dedicated keychain](macos-keychain.md)) |
| `wincred` | Windows Credential Manager |
| `kwallet` / `secret-service` | Linux (KDE Wallet / GNOME Keyring via freedesktop Secret Service) |
| `file` | encrypted files, password prompted on the terminal (`filePasswordPrompt`) |

Selection order (`cmd/root.go` `initConfig`), highest first:

1. the `--backend` flag;
2. the `NOKEY_BACKEND` environment variable;
3. `default_backend` in `config.yaml`.

On macOS the library is configured with `KeychainTrustApplication: true` and nokey's Touch ID account and service.

## Names and the reserved namespace

`ValidateSecretName` accepts names matching `[A-Za-z0-9_][A-Za-z0-9_.-]*`, at most 128 characters. It rejects:

- names with the `__nokey_` prefix;
- names that `env.ReservedSecretName` reports, i.e. a name that, injected as an environment variable, would change which code a command runs or where it connects. See [Command execution and output redaction](exec-and-redaction.md#reserved-variable-names).

nokey keeps **its own state in the same keyring under `__nokey_`**:

- the PIN hash and the failure counter;
- the audit log keys;
- the approved policy digest;
- the proxy CA private key;
- the migration sentinels.

The public methods `Set`, `Get` and `Delete` refuse that prefix. `List` hides it, so `nokey list` and MCP `list_secrets` never show it. nokey's own code uses `SetInternal`, `GetInternal` and `DeleteInternal`, which *require* the prefix.

As a result, anything that can run `nokey` can't replace or delete the PIN hash, for example to turn the PIN off.

## Reads, caching and access prompts

- `get` caches items in memory for the life of the `Store`.
- On a store using a dedicated keychain, the first uncached read runs the one-time build-trust hook.
- A missing key becomes the error `secret not found: NAME`, which `IsNotFound` checks for.
- `GetMany(names)` reads only the requested values. That matters because each read can raise an OS access prompt.
- `GetAll` is `GetMany(List())`.
- `AuthenticatedGetAll` and `AuthenticatedGetMany` add PIN verification first. See [Human presence, PIN and sessions](../security/human-presence-and-pin.md).

## Rename

The keyring has no native rename, so `Rename(old, new)`:

1. validates `new` and refuses `__nokey_` sources;
2. checks that `new` doesn't already exist by **listing keys rather than reading a value**, so no prompt appears;
3. copies the value to `new` and reads it back to compare;
4. only then removes `old`.

If the comparison or the removal fails, the copy is removed again, so a failed rename never leaves the value under both names.

Policy rules match secret names, so a rename can change what a command may read. The MCP `rename_secret` tool therefore always asks the user ([MCP server](mcp-server.md)).

## File backend directory

The file backend treats *every file* in its directory as a secret. Its directory is therefore `~/.config/nokey/keyring`, separate from `config.yaml`, `policies.yaml`, the audit log and session files.

Older releases used `~/.config/nokey` itself. On every `keyring.New`, whatever the backend, `migrateFileBackendDir` moves the old entries:

- It does nothing if the new directory already exists or there is nothing to move.
- It skips reserved config, audit and session files, dot-files and subdirectories.
- Each file is copied to a temp file, fsynced, checked by size and renamed into place, and only then is the original removed. A failure aborts with the originals untouched.

Both paths come from `os.UserHomeDir()` plus `/.config/nokey`, not from `config.ConfigDir()`. On Windows they differ from `%APPDATA%\nokey`. See [Configuration](../reference/configuration.md).

## Tests

- `internal/keyring/keyring_test.go` uses `NewWithRing` with in-memory rings to cover names, the reserved prefix, rename rollback and caching.
- `migrate_filedir_test.go` covers the directory migration.

Related: [macOS dedicated keychain and Touch ID](macos-keychain.md), [Configuration](../reference/configuration.md), [Threat model](../security/threat-model.md).
