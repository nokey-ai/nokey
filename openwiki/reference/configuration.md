---
type: reference
title: Configuration and on-disk layout
description: The config.yaml schema and its defaults, lenient versus strict loading (`nokey config validate`), the config directory on each OS, and which nokey state lives in files and which in the OS keyring. Also notes the security consequence that config can only add gates.
tags: [configuration, config-yaml, filesystem, keyring, reference]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-86bd2fa383fab6c3cbb59c42
    resource: repo://cmd/config_cmd.go
  - id: openwiki-source-964e771d97b07ae87895d623
    resource: repo://cmd/exec.go
  - id: openwiki-source-f42f58941c9d73aeae96953f
    resource: repo://internal/audit/audit.go
  - id: openwiki-source-a8910515ddd14810ad43f5c1
    resource: repo://internal/config/config.go
  - id: openwiki-source-ac1afc23925ae59919b2f8be
    resource: repo://internal/keyring/keyring.go
  - id: openwiki-source-c3138a2e20a1bb95abc1c522
    resource: repo://internal/session/session.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Configuration and on-disk layout

## Config directory

`config.ConfigDir()` (`internal/config/config.go`) is `~/.config/nokey`. On Windows it is `%APPDATA%\nokey` when `APPDATA` is set. Most of nokey reaches it through `getConfigDir()` in `cmd`, or uses it as the default (for example `audit.AuditLogDir = config.ConfigDir`).

| Path (under the config dir unless noted) | Owner | Contents |
|---|---|---|
| `config.yaml` | `internal/config` | settings (below) |
| `policies.yaml` | `internal/policy` | command/secret rules and proxy rules ([Policy file](../security/policies.md)) |
| `audit.log`, `chain_head.json` | `internal/audit` | encrypted, HMAC-chained audit log ([Audit log](../security/audit-log.md)) |
| `ca/ca-cert.pem` | `internal/proxy` | proxy CA certificate; the key is **not** here |
| `backups/*.enc` | `internal/backup` | sealed pre-migration snapshots |
| `~/.config/nokey/session_ticket` | `internal/session` | PIN session ticket |
| `~/.config/nokey/keyring/` | `internal/keyring` | entries for the `file` backend |
| `~/Library/Keychains/<name>.keychain-db` | macOS keychain | dedicated keychain ([macOS](../architecture/macos-keychain.md)) |

The session ticket and the file-backend directory are built from `os.UserHomeDir()` plus `.config/nokey`, **not** from `ConfigDir()`. On Windows they therefore land under the home directory, not `%APPDATA%`.

### What lives in the keyring instead

Values whose theft or tampering would defeat a gate are kept in the OS keyring under the reserved `__nokey_` prefix. Any program running as the user can rewrite a file, but not these entries.

- The PIN hash (`__nokey_pin_hash__`) and its failure-backoff state.
- The audit log encryption key and chain-head checkpoint (`__nokey_audit_encryption_key__`, `__nokey_audit_chain_head__`).
- The approved policy digest (`__nokey_policy_digest__`).
- The proxy CA private key (`__nokey_proxy_ca_key__`).
- Migration sentinels.

See [Secret storage](../architecture/secret-storage.md#names-and-the-reserved-namespace).

## `config.yaml` schema

| Key | Default | Meaning |
|---|---|---|
| `default_backend` | `""` (platform default) | keyring backend; overridden by `NOKEY_BACKEND`, then `--backend` |
| `service_name` | `nokey` | keyring service name |
| `redact_by_default` | `false` | `nokey exec` redacts output unless `--redact` is set explicitly |
| `require_auth` | `false` | deprecated; forces the PIN method |
| `audit.enabled` | `false` | turn on the audit log |
| `audit.max_entries` | `1000` | retention cap |
| `audit.retention_days` | `90` | retention age |
| `auth.default_method` | `""` (auto) | `pin` or `none`. Auto means PIN if one is set. `oauth`/`both` were removed in v0.9.0 and are rejected. |
| `auth.session_ttl` | `15m` | how long a PIN session ticket lasts; at most `8h` |
| `auth.skip_confirm` | `false` | skip `exec`'s y/N prompt |
| `auth.auto_mint_token` | `false` | MCP: one approval mints a 1h session token ([Approvals and session tokens](../security/approval-and-tokens.md)) |
| `auth.use_biometrics` | true on macOS | Touch ID for the dedicated keychain |
| `auth.biometrics_only_when_locked` | `false` | skip Touch ID while the dedicated keychain is already unlocked |
| `auth.cli_enforce_policy` | none | **ignored**. Kept only so old configs still load. |
| `keyring.dedicated` | `false` | macOS: use a dedicated keychain file |
| `keyring.name` | `nokey` (when dedicated) | dedicated keychain file name |

### Loading

- `config.Load()`, used at every start-up:
  - A missing file means defaults.
  - Unknown keys are ignored.
  - A parse error makes `cmd` print a warning and continue on `DefaultConfig()`.
- `config.LoadStrict()`, behind `nokey config validate [--json]`:
  - Rejects unknown keys (`KnownFields(true)`) and any invalid or removed `auth.default_method`.
  - `config validate` also validates `policies.yaml`.

### Config can only add gates

`config.yaml` is an ordinary file that any process running as the user can rewrite. So nothing in it can *weaken* a gate:

- `default_method: none` does not turn off a stored PIN.
- `--auth-method` can't drop a factor.
- `cli_enforce_policy: false` no longer switches off policy checks in `nokey exec`.

Only the keyring-held values above and human confirmation can change what is allowed. See [Threat model](../security/threat-model.md).

Related: [Secret storage](../architecture/secret-storage.md), [Policy file](../security/policies.md), [Audit log](../security/audit-log.md), [Human presence, PIN and sessions](../security/human-presence-and-pin.md).
