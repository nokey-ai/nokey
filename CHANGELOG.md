# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2] - 2026-05-21

### Security
- Proxy CONNECT now validates the TLS SNI and inner request `Host`
  header against the CONNECT-line host. Previously a client could
  CONNECT to an allow-listed host (binding that host's rules and
  injected headers to the tunnel) and then send inner requests for
  any other host — the proxy would still inject the allow-listed
  host's secrets because rule matching keyed off the outer host. SNI
  mismatch terminates the tunnel; inner `Host` mismatch returns 421
  Misdirected Request and skips the upstream call. Literal-IP
  CONNECT hosts are exempt from the SNI check (RFC 6066).
- Pin Go toolchain to 1.26.3, closing 9 stdlib vulnerabilities
  reachable from nokey under 1.26.1: GO-2026-4865/4866/4946/4947
  (crypto/x509), GO-2026-4870 (crypto/tls KeyUpdate DoS), GO-2026-4918
  (net/http HTTP/2 loop), GO-2026-4971 (net Dial NUL panic on Windows),
  GO-2026-4865/4980/4982 (html/template XSS in the OAuth callback page).
- MCP `HandleExec` now consults the policy before reading any secret
  values. Previously it called `store.GetAll()` first, so a request
  policy ultimately denied still unlocked the keyring and pulled every
  secret into memory. New ordering: list names → filter by `only`/
  `except` → policy check → token/approval → fetch surviving values.
- OAuth callback state comparison now uses `subtle.ConstantTimeCompare`
  instead of string `!=`, removing a faint timing oracle on the CSRF
  token. Practical exposure was small (32 random bytes) but a secrets
  manager should not offer any.

### Fixed
- `nokey set --stdin` now preserves multi-line values. Previously
  `bufio.Scanner` returned only the first line, so piping a PEM
  block, JSON service-account, or any newline-containing secret
  silently stored just the first line.
- Concurrent `audit.Record` calls (e.g. parallel MCP tool calls) no
  longer break the hash chain. The load-head / append / save-head
  sequence is now serialized; two concurrent callers could previously
  both append with the same `prev_hmac` and one chain-head write
  would clobber the other, producing permanent "chain break"
  warnings on subsequent loads.
- Audit chain verifier now warns when the log file has more entries
  than the chain head records. Truncation was already flagged; the
  append case relied on the encrypted-payload check incidentally
  failing on the crafted bytes, which isn't a guaranteed signal.
- Audit encryption-key cache holds its mutex across the load. The
  previous double-checked-lock dropped the lock between the nil check
  and the load, so two concurrent first callers could both write to
  the keyring — causing an extra user-visible keychain prompt on
  fresh installs.
- Proxy `Stop()` now drains in-flight CONNECT goroutines before
  clearing the secrets map. Hijacked TLS conns are not tracked by
  `http.Server.Shutdown`, so in-flight ResolveHeaders calls could
  read a nil map and silently drop injected headers from concurrent
  requests.
- Proxy CONNECT now skips the upstream RoundTrip when
  `ResolveHeaders` fails. The 502 was already returned to the
  client, but execution still fell through to the upstream call
  without the intended header.
- Redact `Run()` now waits for its three spawned goroutines (SIGWINCH
  handler, signal forwarder, stdin→PTY copy) before returning. They
  previously outlived the call, racing with any caller that swapped
  `os.Stdin` after `Run` returned (race detector flagged this in
  `TestRun_NoSecrets` / `TestRun_BasicExecution`).
- `keyring.Store.cache` map is now guarded by a mutex. Safe today
  because MCP creates a fresh `Store` per request, but any future
  caller that retains a `Store` across goroutines would race.

### Changed
- `nokey exec` now enforces `policies.yaml` rules. Previously the policy
  file was honoured only by the MCP server and the proxy, so a user who
  wrote rules expecting them to apply at the CLI was silently bypassed.
  When no `policies.yaml` exists the behaviour is unchanged (allow-all).
  To restore the old CLI-bypass behaviour, set
  `auth.cli_enforce_policy: false` in `config.yaml`.
- File backend: store keyring entries in `~/.config/nokey/keyring/` instead
  of the parent config dir. The library treated every file in `FileDir`
  as a keyring entry, so once `nokey init` (or audit/session) wrote
  `config.yaml`/`policies.yaml`/`audit.log`/`session_ticket` alongside
  secrets, `nokey list` would show those as fake "secrets" and `nokey
  exec`/`mcp` failed with `illegal base64 data`. Existing file-backend
  installs are migrated automatically on first run; aux files stay put.
- Integration HTTP client now has a 30s default timeout. The caller's
  context deadline still applies; this is defence in depth against a
  caller that forgets to set one.
- Proxy now uses a per-instance forward transport (`Server.SetTransport`)
  instead of mutating `http.DefaultTransport`. Production behaviour
  unchanged — `forwardTransport()` falls back to `http.DefaultTransport`
  when unset — but tests that previously swapped the global no longer
  race with in-flight CONNECT goroutines.

## [0.2.0] - 2026-03-24

### Added
- Homebrew cask tap (`nokey-ai/homebrew-tap`) with GoReleaser auto-publish
- `make check` convenience target (test + vet + lint)
- Test coverage for `keychain migrate` command (6 tests)
- `nokey init` command to generate starter config and policies files
- `nokey completion` command for bash, zsh, fish, and powershell
- `nokey list --json` and `nokey status --json` for machine-readable output
- `nokey version --long` showing commit, build date, Go version, and platform
- Cross-platform config directory: `%APPDATA%\nokey` on Windows
- Example `policies.yaml` with Anthropic, OpenAI, and GitHub rules
- GitHub Actions release workflow triggered by `v*` tags
- CHANGELOG.md

### Changed
- Bump Go 1.24 → 1.26 (post-quantum TLS defaults, Green Tea GC)
- Bump GitHub Actions to Node.js 24 (checkout v6, setup-go v6, golangci-lint-action v9, goreleaser-action v7)
- Migrate golangci-lint config to v2 format
- Release workflow uses GitHub App token instead of PAT for tap publishing
- README documents `init`, `completion`, `--json`, and `version --long`
- `config validate` detects unknown YAML keys (typos)
- Error messages now include actionable hints (e.g., "run `nokey status`")
- Standardized error wrapping across all commands (lowercase, `%w`)
- Config directory resolution extracted to `config.ConfigDir()` for reuse

### Fixed
- Skip `MigrateAllItems` tests on non-macOS (function is darwin-only no-op)
- Fix lint: ineffectual assignment, error strings ending with newlines, unchecked Close()
- Redact `ClientSecret` fields from config.yaml on save
- Bare `return err` in MCP server startup now wrapped with context

### Security
- Bump `buger/jsonparser` v1.1.1 → v1.1.2 (DoS vulnerability, Dependabot #3)
- Bump Go 1.24.0 → 1.24.13 (8 stdlib CVEs in crypto/tls, net/url, crypto/x509)
- `.gitignore` now excludes `policies.yaml`, `*.key`, `*.crt`, `*.pem`

## [0.1.0] - 2025-01-01

### Added
- Core secret management: `set`, `get`, `list`, `delete`, `import`, `export`
- OS-native keyring storage (macOS Keychain, Windows Credential Manager, Linux keyrings)
- PIN-based zero-trust authentication with Argon2id hashing
- Sudo-style session caching to reduce PIN re-entry
- OAuth 2.0 authentication (GitHub and custom OIDC providers)
- `nokey exec` — run subprocesses with secrets injected as environment variables
- Output redaction replacing secret values with `[REDACTED:KEY_NAME]`
- Encoding-aware redaction (base64, URL-encoded, hex)
- Scoped policies to gate secret access by command pattern
- Approval gateway prompting users before secret injection
- Session-scoped access lease tokens to reduce approval fatigue
- HTTP/HTTPS intercept proxy injecting secrets into API headers
- `--isolate` egress filtering blocking network access without proxy rules
- MCP (Model Context Protocol) server for AI assistant integration
- Service-aware MCP integration framework with GitHub tools
- Auto-minting of MCP session tokens on first approved call
- macOS Keychain trust and migration commands
- Audit logging with JSON/CSV export and retention policies
- `nokey status` and `nokey config validate` commands
- Best-effort memory zeroing for secret values
- golangci-lint CI, comprehensive test suite (88%+ coverage)
- goreleaser config for cross-platform releases (darwin/linux/windows × amd64/arm64)
