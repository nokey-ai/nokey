# Security Gap Remediation — Changes

## Overview

This branch addresses security gaps in nokey's zero-trust model by adding secret lifecycle tracking, tighter session token defaults, per-secret auth enforcement, and defense-in-depth improvements to the proxy.

---

## New Features

### `--dry-run` flag for exec

Show what secrets would be injected and which auth method applies without executing the command.

```bash
nokey exec --dry-run --only OPENAI_API_KEY -- claude "do the thing"
```

Output includes: command, auth method, secret names, redaction/isolation status.

### Secret metadata tracking

nokey now tracks `created_at`, `last_accessed`, and `set_count` per secret in `~/.config/nokey/secrets_meta.json`. This enables staleness detection and lifecycle visibility without modifying the keyring.

### `nokey list` shows age and idle time

```
Stored secrets (3):
  OPENAI_API_KEY  (age: 45d, idle: 2d)
  DATABASE_URL    (age: 120d, idle: 95d) [STALE]
  GITHUB_TOKEN    (age: 10d, idle: 1h)
```

Secrets not accessed within `secret_policy.max_idle_days` are marked `[STALE]`.

### `nokey status` expanded health checks

New fields: OAuth provider status, audit system health (entry count, warnings), PIN session state, and stale secret count.

```
nokey status:
  Keyring backend:     accessible
  PIN authentication:  configured
  OAuth:               github (valid)
  Session:             active
  Policy:              valid (3 rules, 2 proxy rules)
  Config:              valid
  Secrets stored:      12
  Audit:               enabled
  Audit entries:       142
  Stale secrets:       2 (not accessed in 90+ days)
```

### `nokey audit status` subcommand

Dedicated audit health check without listing entries:

```bash
nokey audit status
nokey audit status --json
```

Shows: enabled state, log file size, entry count, oldest/newest entry, chain integrity, retention config.

### Sensitivity tiers (per-rule `auth_method`)

Policy rules can now override the authentication method for specific command+secret pairs:

```yaml
# ~/.config/nokey/policies.yaml
rules:
  - commands: ["*"]
    secrets: ["PROD_*"]
    auth_method: both     # production secrets always need PIN + OAuth

  - commands: ["claude"]
    secrets: ["OPENAI_API_KEY"]
    auth_method: pin
    approval: never
```

Valid values: `pin`, `oauth`, `both`, `none`. The most restrictive matching rule wins.

### Rate-limited session token minting

After a token is revoked, the same secret-set cannot be re-minted for 60 seconds. This prevents abuse patterns where an AI agent rapidly cycles revoke+mint to bypass TTL. System-initiated re-mints (auto-mint after expiry) bypass this cooldown since they require fresh user approval.

### Proxy upstream certificate fingerprint tracking

The HTTPS proxy now tracks the SHA-256 fingerprint of upstream server certificates. On first connection, the fingerprint is recorded. If it changes on a subsequent connection, an audit event is emitted:

```
proxy:cert_change  api.openai.com  certificate changed: was 3a7f1b2c...9e4d5a6b, now c8d2e1f0...7b3a4c5d
```

Fingerprints persist to `~/.config/nokey/cert_pins.json` across proxy restarts.

---

## Configuration Changes

### New config fields (`~/.config/nokey/config.yaml`)

```yaml
auth:
  auto_mint_ttl_seconds: 300  # override auto-mint token TTL (max 3600, default 300)

secret_policy:
  max_age_days: 180    # warn if secret older than this (0 = disabled)
  max_idle_days: 90    # warn if not accessed in this many days (0 = disabled)
```

### New policy fields (`~/.config/nokey/policies.yaml`)

```yaml
rules:
  - commands: ["*"]
    secrets: ["PROD_*"]
    auth_method: both   # NEW: per-rule auth override
```

---

## Breaking Changes

- **MCP auto-mint TTL reduced from 3600s to 300s.** Session tokens now expire after 5 minutes instead of 1 hour. To restore the old behavior, set `auth.auto_mint_ttl_seconds: 3600` in config.
- **Token re-minting has a 60s cooldown after revocation.** Automated workflows that rapidly revoke and re-mint tokens for the same secrets will see an error. This does not affect normal usage.

---

## Files Changed

| File | Change |
|------|--------|
| `cmd/exec.go` | Added `--dry-run` flag, metadata access recording, policy auth override |
| `cmd/set.go` | Records metadata on secret set |
| `cmd/delete.go` | Removes metadata on secret delete |
| `cmd/import.go` | Records metadata for each imported secret |
| `cmd/list.go` | Shows age/idle columns, stale markers |
| `cmd/status.go` | Added OAuth, audit, session, stale checks |
| `cmd/audit.go` | Added `audit status` subcommand |
| `internal/config/config.go` | Added `AutoMintTTLSecs`, `SecretPolicyConfig` |
| `internal/policy/policy.go` | Added `AuthMethod` field, `RequiredAuthMethod()` |
| `internal/mcpserver/handler.go` | Reduced default TTL, configurable override, cooldown bypass |
| `internal/token/store.go` | Added mint cooldown after revocation, `ClearCooldown()` |
| `internal/proxy/server.go` | Integrated cert tracker into CONNECT handler |

## Files Added

| File | Purpose |
|------|---------|
| `internal/metadata/metadata.go` | Secret lifecycle metadata store |
| `internal/metadata/metadata_test.go` | Tests for metadata store |
| `internal/proxy/certtrack.go` | Upstream certificate fingerprint tracker |
