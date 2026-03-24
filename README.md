# nokey

[![CI](https://github.com/nokey-ai/nokey/actions/workflows/ci.yml/badge.svg)](https://github.com/nokey-ai/nokey/actions/workflows/ci.yml)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Zero-trust secret management for AI coding assistants**

`nokey` stores credentials in OS-native secure storage (macOS Keychain, Windows Credential Manager, Linux keyrings) and provides zero-trust access control with PIN/OAuth authentication and comprehensive audit logging. AI coding assistants can use your secrets without ever seeing the actual values, and you maintain complete control over when and how secrets are accessed.

## Why nokey?

When you use AI coding assistants, you often need to provide API keys, tokens, and other sensitive credentials. Pasting these directly into `.env` files or your terminal exposes them to:

- **Git commits** (accidental check-ins)
- **Command history**
- **AI assistant context windows** (where they could be leaked in responses)
- **Log files and debugging output**

`nokey` solves this with a **zero-trust security model**:

1. **Secrets stored in OS-native secure storage** (encrypted, protected by OS)
2. **PIN or OAuth authentication required** before any secret access
3. **Comprehensive audit logging** of all secret access (encrypted)
4. **Selective secret injection** (only expose what's needed)
5. **Output redaction** to prevent accidental logging
6. **Cannot be bypassed programmatically** - AI assistants cannot access secrets without you

---

## Installation

### Using Go

```bash
go install github.com/nokey-ai/nokey@latest
```

### From Source

```bash
git clone https://github.com/nokey-ai/nokey.git
cd nokey
go build -o nokey
sudo mv nokey /usr/local/bin/
```

### Homebrew

```bash
brew install nokey-ai/tap/nokey
```

---

## Quick Start

```bash
# 0. Create starter config and policies files
nokey init

# 1. Store secrets (prompted securely, no echo)
nokey set OPENAI_API_KEY
nokey set DATABASE_PASSWORD

# 2. Set up PIN authentication (optional but recommended)
nokey auth setup

# 3. Enable audit logging (optional)
# Edit ~/.config/nokey/config.yaml:
#   audit:
#     enabled: true

# 4. Run commands with secrets - you'll be prompted for PIN
nokey exec -- claude "help me build a REST API"

# 5. View audit log
nokey audit list
```

---

## Core Commands

### Setup

```bash
# Generate starter config.yaml and policies.yaml
nokey init

# Overwrite existing files
nokey init --force

# Also set up PIN authentication
nokey init --with-auth
```

### Shell Completions

```bash
# Bash (add to ~/.bashrc)
source <(nokey completion bash)

# Zsh (add to ~/.zshrc)
source <(nokey completion zsh)

# Fish
nokey completion fish | source

# PowerShell
nokey completion powershell | Out-String | Invoke-Expression
```

### Secret Management

```bash
# Store a secret (interactive, secure input)
nokey set OPENAI_API_KEY

# Store from stdin (for piping from password managers)
echo "sk-..." | nokey set OPENAI_API_KEY --stdin
op read "op://Private/OpenAI/key" | nokey set OPENAI_API_KEY --stdin

# List stored secret names (never values)
nokey list

# Delete a secret
nokey delete OPENAI_API_KEY

# Import from .env file
nokey import .env

# Export to shell (use with caution)
eval "$(nokey export --shell bash)"
```

### Execute Commands with Secrets

```bash
# Default: shows confirmation prompt
nokey exec -- claude "analyze this code"

# Only inject specific secrets (most secure)
nokey exec --only OPENAI_API_KEY -- claude "task"

# Exclude sensitive secrets
nokey exec --except DATABASE_PASSWORD,AWS_SECRET -- script.py

# Skip confirmation (if you trust the command)
nokey exec --yes -- cursor .

# Enable output redaction
nokey exec --redact -- python script.py

# Combine for maximum security
nokey exec --only GITHUB_TOKEN --redact -- gh api /user
```

---

## Security Features

### 1. PIN Authentication (Zero-Trust)

PIN authentication ensures that even if an AI assistant runs commands, it **cannot access secrets without you entering your PIN**.

```bash
# Set up PIN (requires interactive terminal - AI can't do this)
nokey auth setup

# Check status
nokey auth status

# Change PIN
nokey auth change

# Disable PIN
nokey auth disable
```

**How it works:**
- PIN is hashed (Argon2id with salt) and stored in OS keyring
- Every secret access requires PIN entry
- Cannot be bypassed programmatically
- AI assistants cannot enter the PIN

**Example workflow:**
```bash
$ nokey exec -- python script.py

🔐 Authentication Required
Enter your nokey PIN to access secrets: ****

# Only after you enter correct PIN does the script run
```

**Verify it can't be bypassed:**
```bash
# AI cannot automate PIN setup
echo -e "1234\n1234" | nokey auth setup
# Error: PIN setup requires an interactive terminal

# AI cannot pipe PIN to bypass auth
echo "1234" | nokey exec -- command
# Error: authentication requires an interactive terminal

# --yes does not bypass PIN
nokey exec --yes -- command
# Still prompts for PIN when configured
```

### 2. OAuth Authentication

Authenticate with OAuth providers (GitHub, custom) as an alternative or addition to PIN.

```bash
# Set up GitHub OAuth (opens browser for authorization)
nokey auth oauth setup --provider github \
  --client-id YOUR_GITHUB_CLIENT_ID \
  --client-secret YOUR_GITHUB_CLIENT_SECRET

# Set up custom OAuth provider (--provider generic or --provider custom)
nokey auth oauth setup --provider generic \
  --auth-url https://provider.com/oauth/authorize \
  --token-url https://provider.com/oauth/token \
  --userinfo-url https://provider.com/oauth/userinfo \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --scopes openid,profile,email

# Check OAuth token status and expiry
nokey auth oauth status

# Manually refresh OAuth token (happens automatically on exec if expired)
nokey auth oauth refresh --provider github

# Logout (removes both token and credentials)
nokey auth oauth logout --provider github
```

**Flexible authentication modes:**
- **PIN only** - Traditional PIN authentication
- **OAuth only** - Use GitHub or custom OAuth provider
- **Both (2FA)** - Require both PIN and OAuth
- **Per-command** - Choose auth method per execution

```bash
# Use default auth method from config
nokey exec -- command

# Override to use OAuth only
nokey exec --auth-method oauth -- command

# Require both PIN and OAuth (2FA)
nokey exec --auth-method both -- command
```

### 3. Confirmation Prompts

By default, nokey shows what secrets will be exposed and asks for confirmation:

```bash
$ nokey exec -- ./script.sh

Command './script.sh' will have access to 4 secret(s):
  • OPENAI_API_KEY
  • DATABASE_PASSWORD
  • GITHUB_TOKEN
  • AWS_SECRET_ACCESS_KEY

⚠️  The subprocess will be able to read these secrets from its environment.
   Only proceed if you trust this command.

Continue? [y/N]:
```

**Skip confirmation:**
- Use `--yes` flag to skip the confirmation prompt

### 4. Selective Secret Injection

```bash
# Only inject what's needed (most secure)
nokey exec --only OPENAI_API_KEY,GITHUB_TOKEN -- command

# Inject all except sensitive ones
nokey exec --except DATABASE_PASSWORD,PROD_AWS_KEY -- command
```

### 5. Output Redaction

```bash
# Redact secret values from output
nokey exec --redact -- sh -c 'echo "My key is: sk-123"'
# Output: My key is: [REDACTED:OPENAI_API_KEY]
```

**Note:** Redaction uses string matching. Base64/URL encoding will bypass it. This is defense-in-depth, not a security guarantee.

---

## Audit Logging

Track when secrets are accessed, by whom, and with what authentication method. All audit logs are encrypted and stored in your OS keyring.

### Enable Audit Logging

Edit `~/.config/nokey/config.yaml`:

```yaml
audit:
  enabled: true
  max_entries: 1000      # Maximum entries to keep
  retention_days: 90     # Auto-delete entries older than this
```

### Audit Commands

```bash
# List recent audit entries
nokey audit list

# Filter by time
nokey audit list --since 1h   # Last hour
nokey audit list --since 1d   # Last day
nokey audit list --since 1w   # Last week
nokey audit list --since 1m   # Last month

# Filter by secret name
nokey audit list --secret OPENAI_API_KEY

# Filter by command
nokey audit list --command claude

# Filter by operation
nokey audit list --operation exec

# Limit results
nokey audit list --limit 50

# Export to JSON
nokey audit export --format json --output audit.json

# Export to CSV
nokey audit export --format csv --output audit.csv

# Export with filters
nokey audit export --format json --since 7d --secret API_KEY

# Clear audit log (requires authentication)
nokey audit clear
```

### What Gets Logged

Each audit entry contains:
- **Timestamp** (UTC)
- **Secret names accessed** (never values)
- **Command executed**
- **Authentication method used** (PIN, OAuth, both, none)
- **Success/failure status**
- **User and system info** (username, hostname, process ID)
- **Error message** (if failed)
- **Operation type** (exec, set, delete, import, auth)

### Example Audit Output

```
Audit Entries (3):

[1] ✓ 2025-01-15 14:23:45 UTC
    Operation: exec
    Command:   claude
    Secrets:   OPENAI_API_KEY, GITHUB_TOKEN
    Auth:      pin
    User:      user@hostname (PID: 12345)

[2] ✗ 2025-01-15 14:20:12 UTC
    Operation: exec
    Command:   python script.py
    Secrets:   DATABASE_PASSWORD
    Auth:      pin
    User:      user@hostname (PID: 12340)
    Error:     authentication failed: incorrect PIN

[3] ✓ 2025-01-15 14:15:33 UTC
    Operation: set
    Command:   set
    Secrets:   NEW_API_KEY
    Auth:      none
    User:      user@hostname (PID: 12320)
```

---

## Configuration

Config file location: `~/.config/nokey/config.yaml`

### Full Configuration Example

```yaml
# Default keyring backend (empty = system default)
default_backend: ""

# Enable output redaction by default
redact_by_default: false

# Custom service name for keyring entries
service_name: "nokey"

# Audit logging configuration
audit:
  enabled: true
  max_entries: 1000
  retention_days: 90

# Authentication configuration
auth:
  default_method: "pin"  # pin, oauth, both, or none

  # OAuth provider selection
  # Note: OAuth tokens and credentials are stored in OS keyring after running
  # 'nokey auth oauth setup --provider <name> --client-id ... --client-secret ...'
  # This config just tracks which provider is enabled
  oauth:
    github:
      enabled: true  # Use GitHub OAuth when auth_method is "oauth"

    custom:
      enabled: false  # Use custom OAuth provider when auth_method is "oauth"

# Legacy: use auth.default_method instead
require_auth: false  # Deprecated, kept for backward compatibility
```

### Keyring Backend Options

Available backends:
- **(empty)** - System default (recommended)
- **`keychain`** - macOS Keychain
- **`wincred`** - Windows Credential Manager
- **`kwallet`** - KDE Wallet
- **`secret-service`** - freedesktop.org Secret Service (GNOME Keyring)
- **`file`** - Encrypted file (requires password)

```bash
# Via flag
nokey --backend file set API_KEY

# Via environment variable
export NOKEY_BACKEND=file
nokey set API_KEY
```

---

## Use Cases

### With AI Coding Assistants

#### Claude Code
```bash
# Maximum security: PIN + selective injection + redaction
nokey exec --only OPENAI_API_KEY --redact -- claude "help me build an API"
```

#### Cursor
```bash
# Review secrets before allowing access
nokey exec -- cursor .
```

#### Aider
```bash
# Only expose Anthropic API key
nokey exec --only ANTHROPIC_API_KEY -- aider --model claude-3-opus
```

#### GitHub Copilot CLI
```bash
nokey exec --only GITHUB_TOKEN -- gh copilot suggest "optimize this"
```

### CI/CD Pipelines

```bash
# Store deployment credentials
nokey set AWS_ACCESS_KEY_ID
nokey set AWS_SECRET_ACCESS_KEY
nokey set DATABASE_URL

# Run deployment (requires PIN in interactive mode)
nokey exec -- ./deploy.sh

# For automation: use --yes with specific secrets only
nokey exec --yes --only AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY -- ./deploy.sh
```

### Development vs Production

```bash
# Development: exclude production secrets
nokey exec --except PROD_DATABASE_URL,PROD_AWS_KEY -- npm run dev

# Production deployment: only production secrets
nokey exec --only PROD_DATABASE_URL,PROD_AWS_KEY -- npm run deploy
```

---

## MCP Server Mode

Run nokey as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server so AI tools can access secrets through a structured, audited interface.

### Setup

Add nokey to your Claude Code configuration (`~/.claude/claude_code_config.json`):

```json
{
  "mcpServers": {
    "nokey": {
      "command": "nokey",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_secrets` | List stored secret key names (not values) |
| `exec` | Execute a command with secrets as environment variables |
| `exec_with_secrets` | Execute with `${{NOKEY:SECRET_NAME}}` placeholder injection |
| `mint_token` | Create a short-lived access lease token |
| `revoke_token` | Revoke an access lease token |
| `list_tokens` | List active access lease tokens |
| `start_proxy` | Start the HTTP/HTTPS secret-injection proxy |
| `stop_proxy` | Stop the running proxy |
| `github_api` | Call any GitHub API endpoint with automatic token injection |
| `github_create_issue` | Create a GitHub issue |
| `github_create_pr` | Create a GitHub pull request |
| `github_list_issues` | List repository issues |
| `github_list_prs` | List repository pull requests |
| `github_get_file` | Get a file from a GitHub repository |

All output from `exec` and `exec_with_secrets` is automatically redacted — secret values are replaced with `[REDACTED:KEY_NAME]`.

### Session Tokens

Session tokens allow a single user approval to cover multiple secret accesses within a session:

```yaml
# ~/.config/nokey/config.yaml
auth:
  auto_mint_token: true  # Auto-mint a session token on first MCP approval
```

When `auto_mint_token` is enabled, the first time an AI tool requests secret access, the user approves once. A session token (TTL: 1 hour) is minted and subsequent requests use it without re-prompting.

Manual token management is also available via the `mint_token`, `revoke_token`, and `list_tokens` tools. Tokens support TTL (max 3600s) and max-use limits.

---

## Proxy Mode

The HTTP/HTTPS proxy intercepts outbound requests and injects secrets into headers based on rules — AI agents never handle credentials directly.

### Setup

```bash
# 1. Generate the local CA certificate
nokey proxy init-ca

# 2. Trust the CA (prints OS-specific instructions)
nokey proxy trust-ca

# 3. Start the proxy
nokey proxy start
```

### Proxy Rules

Define proxy rules in `~/.config/nokey/policies.yaml`:

```yaml
proxy:
  rules:
    - hosts: ["api.openai.com"]
      headers:
        Authorization: "Bearer $OPENAI_API_KEY"

    - hosts: ["*.anthropic.com"]
      headers:
        x-api-key: "$ANTHROPIC_API_KEY"

    - hosts: ["api.github.com"]
      headers:
        Authorization: "token $GITHUB_TOKEN"
      approval: never  # skip per-request approval
```

### Using the Proxy

```bash
# Set environment variables (printed by `proxy start`)
export http_proxy=http://127.0.0.1:<port>
export https_proxy=http://127.0.0.1:<port>

# Now any HTTP client routes through the proxy
curl https://api.openai.com/v1/models  # Authorization header injected automatically
```

### Egress Isolation

Block outbound network access to hosts without a proxy rule:

```bash
nokey exec --isolate -- python script.py
```

This starts a local proxy with `--isolate` that rejects connections to any host not covered by a proxy rule.

---

## Policy File

`~/.config/nokey/policies.yaml` controls which commands can access which secrets, approval requirements, and proxy rules.

### Full Reference

```yaml
# Global default approval mode (always, never, or omit for default)
approval: always

# Command-to-secret access rules
rules:
  - commands: ["claude", "cursor"]
    secrets: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
    approval: never           # Skip approval prompt for these

  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
    approval: always          # Always prompt
    token_required: true      # Require a session token (no per-call approval fallback)

  - commands: ["*"]
    secrets: ["*"]
    approval: always          # Catch-all: approve everything else

# Proxy header injection rules
proxy:
  rules:
    - hosts: ["api.openai.com"]
      headers:
        Authorization: "Bearer $OPENAI_API_KEY"

    - hosts: ["*.example.com"]
      headers:
        x-api-key: "$API_KEY"
      approval: never
```

Commands are matched by base name (full paths are stripped). Secrets and commands support glob patterns (`*`, `?`). Rules are evaluated top-down; the first match wins. If no rule matches, access is denied (fail-closed).

---

## Diagnostic Commands

### `nokey status`

Unified health check showing PIN, keyring, config, policy, and secrets status:

```bash
$ nokey status
nokey status:
  PIN authentication:  configured
  Keyring backend:     accessible
  Config:              valid
  Policy:              valid (3 rules, 2 proxy rules)
  Secrets stored:      12

# Machine-readable output
$ nokey status --json
{"pin_configured":true,"keyring_accessible":true,"config_valid":true,...}
```

### `nokey list`

```bash
# List stored secret names (never values)
nokey list

# Machine-readable output
$ nokey list --json
["OPENAI_API_KEY","DATABASE_PASSWORD","GITHUB_TOKEN"]
```

### `nokey version`

```bash
# Short version
$ nokey version
nokey v0.2.0

# Detailed build info
$ nokey version --long
nokey v0.2.0
  commit:   abc1234
  built:    2025-01-15T10:30:00Z
  go:       go1.24
  platform: darwin/arm64
```

### `nokey config validate`

Validate config and policy files without side effects. Detects unknown YAML keys (typos):

```bash
$ nokey config validate
config.yaml: OK
policies.yaml: OK
```

Exits with code 1 if either file is invalid.

---

## Threat Model

### What nokey protects against ✅

#### Accidental exposure in AI assistant context windows
- Secrets are never visible in the text you share with AI
- AI assistants see `OPENAI_API_KEY` as an environment variable name, not the value

#### Accidental git commits
- No `.env` files with secrets to accidentally commit
- Secrets stored in OS-native secure storage, outside your repository

#### Command history exposure
- Secrets aren't typed in plaintext on the command line
- Secure input prompts don't echo to terminal

#### Unauthorized automated access
- PIN authentication cannot be bypassed programmatically
- AI assistants cannot access secrets without human PIN entry
- OAuth tokens require browser interaction

#### Unaudited secret access
- Comprehensive audit logging (if enabled)
- Know exactly when, how, and by whom secrets were accessed

#### Log file leakage
- With `--redact` flag, secret values are replaced with `[REDACTED:KEY_NAME]`
- Prevents accidental logging of credentials

### What nokey does NOT protect against ❌

#### Determined exfiltration by malicious code
- If you run malicious code with `nokey exec` and enter your PIN, that code has full access to environment variables
- The subprocess can read secrets and exfiltrate them
- `nokey` is not a sandbox or security boundary
- **Mitigation**: Only run trusted code, use `--only` to limit exposure

#### Memory dumps and debugging
- Secrets exist in process memory while the subprocess runs
- Debuggers and memory dump tools can read them

#### Encoding bypass of redaction
- The `--redact` flag uses simple string matching
- Base64 encoding, URL encoding, or other transformations bypass it
- Redaction is defense-in-depth, not a security guarantee

#### OS-level attacks
- If your OS account is compromised, attackers can read the keyring
- OS keyring security depends on your system's security

### Security Best Practices

1. **Set up PIN authentication**
   ```bash
   nokey auth setup
   ```
   This prevents AI assistants from accessing secrets without you

2. **Use selective injection**
   ```bash
   nokey exec --only NEEDED_KEY -- command
   ```
   Only expose secrets that are actually needed

3. **Enable audit logging**
   ```yaml
   # ~/.config/nokey/config.yaml
   audit:
     enabled: true
   ```
   Track all secret access for security monitoring

4. **Only run trusted code**
   - Treat `nokey exec` like `sudo` - only use with code you trust
   - Review code before running it with access to secrets

5. **Rotate secrets regularly**
   - Don't treat `nokey` as permanent secret storage
   - Rotate API keys and tokens on a regular schedule

6. **Use `--redact` for defense-in-depth**
   - While not foolproof, it catches many accidental exposures
   - Especially useful for logging and debugging output

7. **Review audit logs**
   ```bash
   nokey audit list --since 7d
   ```
   Regularly check for unexpected secret access

---

## Comparison to Alternatives

### vs. `.env` files

| Feature | nokey | .env files |
|---------|-------|------------|
| OS-native secure storage | ✅ | ❌ |
| No files to accidentally commit | ✅ | ❌ |
| Hidden from AI context | ✅ | ❌ |
| PIN authentication | ✅ | ❌ |
| Audit logging | ✅ | ❌ |
| Selective injection | ✅ | ❌ |
| Easy to use | ✅ | ✅ |

### vs. `direnv`

`direnv` loads environment variables from `.envrc` files automatically when you `cd` into a directory.

- Still uses plaintext files that can be committed
- Secrets are visible in your shell session permanently
- No integration with OS secure storage
- No authentication or audit logging

**Use direnv for**: Non-secret configuration
**Use nokey for**: Actual secrets and credentials

### vs. `1password-cli` / `op`

1Password CLI is excellent for secret management:

- ✅ Very secure, cloud-synced
- ✅ Team sharing
- ✅ Audit logging
- ❌ Requires 1Password subscription
- ❌ More complex syntax for common operations
- ❌ Cloud dependency

**Use 1Password if**: You need team secret sharing or cloud sync
**Use nokey if**: You want local, simple, zero-dependency secret injection

### vs. HashiCorp Vault

Vault is enterprise-grade secret management:

- ✅ Extremely secure, audited, feature-rich
- ✅ Dynamic secrets, leasing, revocation
- ✅ Enterprise-grade audit logging
- ❌ Complex to set up and operate
- ❌ Requires server infrastructure
- ❌ Overkill for individual developers

**Use Vault if**: You're running production infrastructure
**Use nokey if**: You're an individual developer working locally

---

## How It Works

### 1. Secret Storage

Uses [`99designs/keyring`](https://github.com/99designs/keyring) library to interact with OS-native secure storage:

- **macOS**: Keychain (protected by FileVault, Touch ID, or password)
- **Windows**: Credential Manager (protected by Windows security)
- **Linux**: freedesktop.org Secret Service (GNOME Keyring, KWallet)
- **Fallback**: Encrypted file with password

### 2. Authentication

**PIN Authentication:**
1. PIN is hashed using Argon2id (with random salt and key-stretching)
2. Hash stored in OS keyring under `__nokey_pin_hash__`
3. When accessing secrets, user is prompted for PIN
4. Entered PIN is hashed and verified using constant-time comparison
5. Must run in interactive terminal (cannot be automated)
6. Legacy SHA-256 hashes are detected and users are prompted to upgrade

**OAuth Authentication:**
1. Local HTTP server started on random port
2. Browser opened to OAuth provider
3. User authenticates and approves
4. OAuth callback received with authorization code
5. Code exchanged for access token
6. Token and client credentials encrypted and stored in keyring
7. Token validated on each secret access (auto-refresh if expired)
8. CSRF protection with state tokens

### 3. Secret Injection

When you run `nokey exec`:
1. Authenticate (PIN or OAuth if required)
2. Retrieve secrets from keyring
3. Filter secrets based on `--only` or `--except` flags
4. Show confirmation prompt (unless `--yes`)
5. Spawn subprocess with secrets merged into environment
6. Forward stdin/stdout/stderr
7. Handle signals (Ctrl+C, etc.) properly
8. Record audit entry (if enabled)
9. Exit with same code as subprocess

### 4. Audit Logging

When audit logging is enabled:
1. Collect audit entry data (timestamp, secrets, command, auth method, user, etc.)
2. Create AuditEntry struct
3. Load existing audit log from keyring
4. Decrypt audit log using NaCl secretbox
5. Append new entry
6. Apply retention policy (max entries, age limit)
7. Encrypt updated log
8. Store back in keyring under `__nokey_audit_log__`

All audit data is encrypted before storage, so even system administrators cannot read audit logs without the nokey encryption key.

### 5. Output Redaction (optional with `--redact`)

1. Allocate a PTY for the subprocess
2. Intercept all output
3. Replace exact matches of secret values with `[REDACTED:KEY_NAME]`
4. Stream to your terminal

**Note**: Simple string matching, can be bypassed by encoding.

---

## Security Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                     USER                            │
│  (Human, Interactive Terminal)                      │
└───────────┬─────────────────────────────────────────┘
            │
            │ 1. nokey exec -- command
            ▼
┌───────────────────────────────────────────────────┐
│              nokey CLI                            │
│  ┌─────────────────────────────────────────────┐ │
│  │ Authentication Layer                        │ │
│  │  • PIN: Prompt for PIN (interactive only)   │ │
│  │  • OAuth: Validate token, refresh if needed │ │
│  │  • Cannot be bypassed programmatically      │ │
│  └─────────────────────────────────────────────┘ │
└───────────┬───────────────────────────────────────┘
            │
            │ 2. Retrieve secrets (after auth)
            ▼
┌───────────────────────────────────────────────────┐
│          OS Keyring (Encrypted)                   │
│  • Secrets stored encrypted                      │
│  • Protected by OS security (Touch ID, password) │
│  • Audit log stored encrypted                    │
│  • OAuth tokens stored encrypted                 │
└───────────┬───────────────────────────────────────┘
            │
            │ 3. Inject secrets as env vars
            ▼
┌───────────────────────────────────────────────────┐
│          Subprocess (command)                     │
│  • Has access to secrets via environment         │
│  • Output optionally redacted                    │
│  • All access audited (if enabled)               │
└───────────────────────────────────────────────────┘
```

**Key Security Properties:**
- ✅ Authentication required (interactive only)
- ✅ All secrets encrypted at rest
- ✅ All access audited
- ✅ AI assistants cannot bypass authentication
- ✅ Selective secret exposure
- ⚠️ Subprocess can read injected secrets (by design)

---

## Development

```bash
# Clone the repository
git clone https://github.com/nokey-ai/nokey.git
cd nokey

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o nokey

# Run
./nokey --help
```

### Project Structure

```
nokey/
├── main.go                    # Entry point
├── cmd/                       # Cobra commands
│   ├── root.go               # Root command setup
│   ├── auth.go               # PIN/OAuth authentication commands
│   ├── audit.go              # Audit log commands
│   ├── set.go                # Store secrets
│   ├── delete.go             # Delete secrets
│   ├── list.go               # List secret names
│   ├── exec.go               # Execute with secrets
│   ├── import.go             # Import from .env
│   ├── export.go             # Export to shell
│   ├── mcp.go                # MCP server and tool handlers
│   ├── proxy.go              # HTTP/HTTPS proxy commands
│   ├── status.go             # Health check command
│   └── config_cmd.go         # Config validation command
├── internal/
│   ├── auth/
│   │   ├── auth.go           # PIN authentication logic
│   │   └── backoff.go        # Brute-force rate limiting
│   ├── audit/
│   │   └── audit.go          # Audit logging, encryption, filtering
│   ├── config/
│   │   └── config.go         # Configuration file handling
│   ├── keyring/
│   │   └── keyring.go        # OS keyring wrapper, name validation
│   ├── exec/
│   │   └── exec.go           # Subprocess execution
│   ├── redact/
│   │   └── redact.go         # Output redaction with PTY
│   ├── policy/
│   │   └── policy.go         # Policy rules, approval, proxy rules
│   ├── proxy/                # HTTP/HTTPS proxy server and CA
│   ├── token/                # Session token store
│   ├── placeholder/          # ${{NOKEY:...}} resolution
│   └── oauth/
│       ├── oauth.go          # OAuth interface, token management
│       ├── github.go         # GitHub OAuth provider
│       ├── generic.go        # Generic OAuth 2.0 provider
│       └── server.go         # Local callback server with CSRF protection
├── README.md
├── LICENSE
└── go.mod
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR guidelines.

### Areas for Contribution

- OAuth provider implementations (GitHub, Google, Azure AD, etc.)
- Additional audit export formats
- Integration examples with other tools
- Documentation improvements
- Bug fixes and performance improvements

---

## License

MIT License - see [LICENSE](LICENSE) file for details

---

## Security

If you discover a security vulnerability, please email security@nokey.ai instead of using the issue tracker.

---

## Credits

Built with:
- [spf13/cobra](https://github.com/spf13/cobra) - CLI framework
- [99designs/keyring](https://github.com/99designs/keyring) - Cross-platform keyring access
- [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go) - Model Context Protocol server
- [creack/pty](https://github.com/creack/pty) - PTY interface for output redaction
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Cryptography (NaCl secretbox)
- [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) - OAuth 2.0 client

Inspired by the need to safely use AI coding assistants without exposing credentials.

---

## FAQ

### Do I need to set up PIN authentication?

No, PIN authentication is optional. However, it's **strongly recommended** if you use AI coding assistants, as it prevents them from accessing secrets without your explicit approval (PIN entry).

### Can AI assistants bypass the PIN?

No. PIN entry requires an interactive terminal and cannot be automated. Even if an AI assistant runs `nokey exec`, it will be blocked at the PIN prompt and cannot proceed.

### What happens if I forget my PIN?

The PIN cannot be recovered. You'll need to:
1. Disable PIN authentication with your current PIN
2. If you truly forgot it, you'll need to delete the PIN hash from your keyring manually
3. Set up a new PIN with `nokey auth setup`

Your secrets remain safe in the keyring regardless.

### Does audit logging affect performance?

Audit logging adds minimal overhead:
- Logs are encrypted and stored in the keyring (one operation per command)
- No network calls or external services
- Typical overhead: <50ms per command

### Can I use nokey in CI/CD?

Yes, but consider:
- **With PIN**: Not suitable for fully automated CI/CD (requires interactive PIN entry)
- **Without PIN**: Use `--yes --only` flags to specify exactly which secrets to inject
- **Best practice**: Use dedicated CI/CD secret management for production, use nokey for local development

### How do audit logs stay private?

Audit logs are:
1. Encrypted using NaCl secretbox before storage
2. Stored in your OS keyring (already encrypted by OS)
3. Encryption key itself is stored in the keyring
4. Double-encrypted: once by nokey, once by OS

Even system administrators cannot read your audit logs without the nokey encryption key.

### What's the difference between PIN and OAuth?

- **PIN**: Simple, local, no external dependencies, you remember a PIN
- **OAuth**: Uses external provider (GitHub), browser-based, can leverage existing auth
- **Both**: Maximum security (2-factor authentication)

Choose based on your threat model and convenience preferences.

### How are OAuth credentials stored?

When you run `nokey auth oauth setup`, nokey stores:
1. **OAuth access token** - encrypted and stored in OS keyring
2. **OAuth refresh token** - encrypted and stored in OS keyring
3. **Client credentials** (client_id & client_secret) - encrypted and stored in OS keyring

**Why store client credentials?**
- Enables automatic token refresh when tokens expire
- Allows `nokey auth oauth refresh` to work without re-entering credentials
- Prevents need to re-authenticate via browser for token refresh

**Security:**
- All stored in OS-native encrypted keyring (same as your secrets)
- Protected by macOS Keychain, Windows Credential Manager, or Linux Secret Service
- Only accessible by your user account
- Removed when you run `nokey auth oauth logout`

**Note:** Client credentials are stored separately from your secrets and are only used for OAuth token management.

### Can I use nokey with Docker?

Yes, but with caveats:
```bash
# This works - secrets available to docker run command
nokey exec -- docker run -e API_KEY myimage

# This doesn't work - secrets not available inside container
nokey exec -- docker run myimage
```

For secrets inside containers, use Docker secrets or inject them at runtime.

---

**Ready to secure your secrets? Get started with `nokey` today!**

```bash
go install github.com/nokey-ai/nokey@latest
nokey auth setup
nokey set YOUR_API_KEY
nokey exec -- your-ai-assistant
```
