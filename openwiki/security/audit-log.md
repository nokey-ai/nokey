---
type: security
title: Audit log
description: nokey's optional audit log. Covers what an entry records (secret names, never values), the encrypted HMAC-chained append-only file with a chain-head checkpoint for detecting truncation and tampering, key storage in the keyring, in-process and cross-process locking, lazy compaction and retention, legacy migration, and which components record events.
tags: [security, audit, logging, hmac, encryption]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-7d5314d324d82f988d8fe576
    resource: repo://cmd/app.go
  - id: openwiki-source-4f2fef6805b2f3fed497f808
    resource: repo://cmd/audit_helper.go
  - id: openwiki-source-86b451d1f9cd856804e1756d
    resource: repo://cmd/audit.go
  - id: openwiki-source-f42f58941c9d73aeae96953f
    resource: repo://internal/audit/audit.go
  - id: openwiki-source-f4fc5209b37c531ecc00dd8a
    resource: repo://internal/audit/lock.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Audit log

`internal/audit` keeps a tamper-evident record of secret access. It is **off by default**; set `audit.enabled: true` in `config.yaml` to turn it on. With it off, every record call does nothing.

## Who records

| Source | Hook | Typical operations |
|---|---|---|
| CLI commands | `App.RecordAudit` (`cmd/app.go`), with the auth method actually used | `exec`, `exec:policy_deny`, `exec:approval_denied`, `set`, `rename`, … |
| MCP server | `AuditFn` → `recordAudit` (`cmd/audit_helper.go`, auth method `keyring_acl`) | `mcp:exec`, `mcp:exec:approval`, `mcp:token_use`, `mcp:grant`, `mcp:auto_mint`, `mcp:mint_token`, `mcp:revoke_token`, `mcp:list_secrets`, `mcp:rename_secret` |
| Proxy | `proxy.AuditFunc` → `recordAudit` | `proxy:https`, `proxy:https:blocked`, `proxy:http:blocked`, `proxy:unauthorized` |

A failed write only causes a warning on stderr (`App.RecordAudit`) or is dropped (`recordAudit`). Auditing never blocks the operation it records.

## Entry contents

`AuditEntry` holds:

- timestamp (UTC);
- `operation`, `command` and `auth_method`;
- `secret_names` (**names only, never values**);
- success, and an error message on failure;
- OS user, hostname and PID.

Token IDs are never logged in full: `revoke_token` records a fingerprint.

## Storage format

| Item | Where |
|---|---|
| Log | `<ConfigDir>/audit.log`, one line per entry |
| Checkpoint | `<ConfigDir>/chain_head.json` holding `{hmac, count}` |
| Encryption key | 32 bytes in the **keyring** (`__nokey_audit_encryption_key__`), created on first use and cached per process. `Clear` doesn't delete it. |
| HMAC key | `HMAC-SHA256(encKey, "nokey-audit-chain-v1")` |

Each line is `base64(secretbox(JSON{entry, prev_hmac}))`, using NaCl secretbox with a random 24-byte nonce.

**Chain.** Each stored entry carries `prev_hmac`: the HMAC of the previous *encrypted line*, or 64 zeros for the first line. After an append, the checkpoint is updated to the new line's HMAC and count (written to a unique temp file, then renamed).

**Verification** (`Load` → `readAndVerifyFile`) does not fail on problems. It returns entries plus **warnings**, which `audit list` and `audit export` print:

- a line that can't be base64-decoded or parsed;
- a `prev_hmac` that doesn't match: a **chain break**;
- lines that fail decryption. When *every* line fails, the warning says the key was likely reset and suggests `nokey audit clear`. When only some fail, it reports possible tampering.
- fewer lines than the checkpoint count: **truncation**;
- more lines than the count: **appended entries**;
- the last line's HMAC differing from the checkpoint: the **last entry was tampered with**.

Forging consistent entries or a consistent checkpoint requires the keyring-held key. A process that can only write files can delete or alter them, but can't do so without the next read noticing.

## Concurrency

- `recordMu` serializes the sequence "load head → append → save head" within one process, for example parallel MCP tool calls.
- `lockAuditDir` takes an advisory `filelock` on `<ConfigDir>/audit.lock` across processes: the CLI, the proxy and the MCP server all write. The lock file is never deleted, because deleting it could let two processes lock different files.
- `Record` fetches the key *before* taking the cross-process lock, so a slow keychain prompt doesn't make other nokey processes wait. Only key creation happens under the lock, so two first writers agree on one key.
- `Load` takes a read-only variant of the lock that falls back to running unlocked when it can't create the lock file.

## Retention and compaction

`audit.max_entries` (default 1000) and `audit.retention_days` (default 90; 0 or less means no age limit) apply **lazily**. When the checkpoint count reaches `2 × max_entries`, `compactFile`:

1. verifies and reads the log;
2. sorts entries by time;
3. drops expired ones and keeps the newest `max_entries`;
4. re-encrypts them with a **fresh chain** into `audit.log.tmp`;
5. renames that into place and resets the checkpoint.

## Clearing and migration

- `nokey audit clear` asks for the PIN when one is configured or `require_auth` is set. It then removes `audit.log` and the checkpoint, plus legacy keyring entries.
- Older releases kept the whole log in the keyring (`__nokey_audit_log__`), and the chain head too (`__nokey_audit_chain_head__`). `Record` migrates both to files once, and does nothing if the file already exists.

## Tests

- `internal/audit/audit_test.go`: chain breaks, truncation, append detection, compaction, migration and concurrent writers.
- `lock_test.go`: locking. Tests override `AuditLogDir` and call `ResetEncKeyCache`.
- `cmd/audit_test.go`: the commands.

Related: [Configuration](../reference/configuration.md), [MCP server](../architecture/mcp-server.md), [Secret-injecting proxy](../architecture/proxy.md), [Threat model](threat-model.md).
