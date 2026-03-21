# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- README documents `init`, `completion`, `--json`, and `version --long`
- `config validate` detects unknown YAML keys (typos)
- Error messages now include actionable hints (e.g., "run `nokey status`")
- Standardized error wrapping across all commands (lowercase, `%w`)
- Config directory resolution extracted to `config.ConfigDir()` for reuse

### Fixed
- Bare `return err` in MCP server startup now wrapped with context

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
