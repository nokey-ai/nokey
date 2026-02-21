# nokey Security Features Demo

## Overview

nokey now includes powerful security features to protect your secrets when using AI coding assistants like Claude Code, Cursor, and aider.

## New Security Features

### 1. **Confirmation Prompt (Default Behavior)**

By default, nokey now shows a confirmation prompt before injecting secrets:

```bash
$ nokey exec -- ./my_script.sh

Command './my_script.sh' will have access to 4 secret(s):
  • ANTHROPIC_API_KEY
  • DATABASE_PASSWORD
  • GITHUB_TOKEN
  • OPENAI_API_KEY

⚠️  The subprocess will be able to read these secrets from its environment.
   Only proceed if you trust this command.

Continue? [y/N]:
```

**Benefits:**
- You see exactly which secrets will be exposed
- You can abort if you don't trust the command
- Prevents accidental secret exposure to untrusted code

**When to use:** Default for all commands

---

### 2. **Selective Injection with `--only`**

Inject **only** specific secrets (most secure):

```bash
$ nokey exec --only OPENAI_API_KEY -- claude "analyze this code"

# Only OPENAI_API_KEY is injected, no other secrets are accessible
# No confirmation prompt (you explicitly chose what to inject)
```

**Test result:**
```
Available secrets:
OPENAI_API_KEY=sk-openai-test-key

# DATABASE_PASSWORD, GITHUB_TOKEN, etc. are NOT available
```

**Benefits:**
- Maximum security - only expose what's needed
- No confirmation prompt (explicit permission)
- Perfect for AI assistants that only need specific keys

**When to use:**
- Running AI assistants that only need specific API keys
- Any untrusted or third-party code
- Scripts from the internet

---

### 3. **Exclusion with `--except`**

Inject all secrets **except** specific ones:

```bash
$ nokey exec --except DATABASE_PASSWORD,AWS_SECRET -- python deploy.py

Command 'python' will have access to 2 secret(s):
  • ANTHROPIC_API_KEY
  • OPENAI_API_KEY

Continue? [y/N]: y
```

**Benefits:**
- Protect sensitive secrets (database passwords, production keys)
- Still get confirmation for what's being injected
- Useful when you need "most but not all" secrets

**When to use:**
- Scripts that need multiple keys but not production secrets
- Development vs. production secret separation

---

### 4. **Skip Confirmation with `--yes`**

Skip the confirmation prompt (original behavior):

```bash
$ nokey exec --yes -- trusted_script.sh

# All secrets injected immediately, no prompt
```

**Benefits:**
- Fast for trusted scripts
- Good for automation/CI/CD
- Original nokey behavior

**When to use:**
- Trusted scripts you run frequently
- Automated workflows
- CI/CD pipelines

⚠️ **Warning:** Use with caution, especially with AI assistants

---

### 5. **Combine with Redaction (Defense in Depth)**

Layer multiple protections:

```bash
$ nokey exec --only GITHUB_TOKEN --redact -- ./script.sh

# If script tries to print the token value:
# Output: My token is: [REDACTED:GITHUB_TOKEN]
```

**Benefits:**
- Selective injection limits exposure
- Redaction prevents accidental logging
- Maximum protection for sensitive operations

**When to use:**
- Running unfamiliar code
- Scripts that might log output
- Extra paranoid security posture

---

## Real-World Examples

### Safe AI Assistant Usage

```bash
# ✅ GOOD: Only give Claude the key it needs
nokey exec --only OPENAI_API_KEY -- claude "help me build an API"

# ✅ GOOD: Review what will be exposed
nokey exec -- cursor .
# (Shows confirmation, you can verify and approve)

# ⚠️ CAREFUL: Skips protection
nokey exec --yes -- aider
# (All secrets exposed without confirmation)

# ❌ AVOID: Running untrusted code with all secrets
./random_internet_script.sh  # Don't do this
nokey exec --yes -- ./random_internet_script.sh  # REALLY don't do this
```

### Production vs. Development

```bash
# Development: Use all dev secrets
nokey exec --except PROD_DATABASE_URL,PROD_AWS_SECRET -- npm run dev

# Production: Only inject production secrets
nokey exec --only PROD_DATABASE_URL,PROD_AWS_SECRET -- npm run deploy
```

### CI/CD Pipeline

```bash
# Automated testing (skip confirmation)
nokey exec --yes --only TEST_API_KEY -- npm test

# Manual deployment (require confirmation)
nokey exec -- ./deploy-to-production.sh
```

---

## Security Decision Tree

```
Need to run a command with secrets?
│
├─ Do you trust this command completely?
│  ├─ YES → Use --yes (fast, no prompt)
│  └─ NO ↓
│
├─ Does it need only specific secrets?
│  ├─ YES → Use --only SECRET1,SECRET2 (most secure)
│  └─ NO ↓
│
├─ Should some secrets be excluded?
│  ├─ YES → Use --except PROD_SECRET1,SECRET2
│  └─ NO ↓
│
└─ Use default (confirmation prompt)
   - Review what will be injected
   - Type 'y' to approve, 'n' to abort
```

---

## Command Reference

```bash
# View available flags
nokey exec --help

# List all stored secrets (names only)
nokey list

# Test what secrets are available to a command
nokey exec --only KEY1 -- sh -c 'env | grep KEY1'

# Dry run: see what would be injected (abort when prompted)
nokey exec -- my_command
# Type 'n' when prompted to abort
```

---

## Why These Features Matter for AI Assistants

**The Problem:**
AI assistants like Claude Code, Cursor, and Copilot can:
- See their environment variables
- Print them in responses
- Accidentally leak them in logs
- Use them in generated code

**The Solution:**
```bash
# Before: All secrets exposed to AI
nokey exec --yes -- claude "help me"
# AI can see: OPENAI_API_KEY, DATABASE_PASSWORD, AWS_SECRET, etc.

# After: Only what's needed
nokey exec --only OPENAI_API_KEY -- claude "help me"
# AI can see: OPENAI_API_KEY only
# AI CANNOT see: DATABASE_PASSWORD, AWS_SECRET, etc.
```

**Result:** AI assistants work perfectly but can only access the secrets they actually need.

---

## Migration Guide

If you're used to the old behavior:

```bash
# Old way (pre-security features)
nokey exec -- claude "task"
# (Injected all secrets immediately)

# New way (backward compatible)
nokey exec --yes -- claude "task"
# (Same behavior, use --yes to skip confirmation)

# Recommended way (more secure)
nokey exec --only OPENAI_API_KEY -- claude "task"
# (Only expose what's needed)
```

---

## Summary

✅ **Default: Confirmation prompt** - Safe by default
✅ **`--only`** - Maximum security, explicit control
✅ **`--except`** - Flexible exclusion
✅ **`--yes`** - Skip confirmation when needed
✅ **Combine with `--redact`** - Defense in depth

**Remember:** nokey can't prevent a subprocess from reading its environment variables. These features help you make conscious decisions about what to expose.
