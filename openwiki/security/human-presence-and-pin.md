---
type: security
title: Human presence, PIN and sessions
description: The CLI's human-only gates. Covers the OS presence dialog (macOS Touch ID or login password), the confirmHuman fallback to a fresh PIN, PIN authentication (Argon2id, TTY-only, exponential backoff stored in the keyring), and sudo-style PIN session tickets bound to the PIN hash and the file's mtime.
tags: [security, pin, presence, touch-id, session, authentication]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-964e771d97b07ae87895d623
    resource: repo://cmd/exec.go
  - id: openwiki-source-bca3af501547eb6853c75a47
    resource: repo://cmd/export.go
  - id: openwiki-source-3ee2d664d6dbd59a209da7a0
    resource: repo://cmd/gate.go
  - id: openwiki-source-248790f154066b38ad98bdc1
    resource: repo://cmd/secret_gate.go
  - id: openwiki-source-b12cba1b5936a1da8739d39c
    resource: repo://internal/auth/auth.go
  - id: openwiki-source-a6237ebdcd71faeac7ca6d59
    resource: repo://internal/auth/backoff.go
  - id: openwiki-source-e12af55390a7e6e951fd052b
    resource: repo://internal/presence/presence_darwin.go
  - id: openwiki-source-8865edae259f173d342c88f5
    resource: repo://internal/presence/presence_other.go
  - id: openwiki-source-20e362a297b9d4acbb99c7a4
    resource: repo://internal/presence/presence.go
  - id: openwiki-source-c3138a2e20a1bb95abc1c522
    resource: repo://internal/session/session.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Human presence, PIN and sessions

nokey's threat model assumes that *another program running as the user* may try to use nokey. An AI agent is the typical example. Such a program can answer a y/N prompt on stdin, answer its own MCP elicitation, or fake a TTY with a pseudo-terminal. So the checks that must prove a human is present rely on factors that program cannot supply:

1. the **OS presence dialog**;
2. a **fresh PIN** typed at a real terminal.

## Presence dialog (`internal/presence`)

`presence.Confirm(ctx, reason)` shows the operating system's own authentication dialog.

- **macOS** (`presence_darwin.go`) uses LocalAuthentication `DeviceOwnerAuthentication` through `touchid-go`: Touch ID where enrolled, otherwise the login password. macOS shows "nokey is trying to <reason>", with the reason capped at 400 bytes.
- Without a GUI session (SSH, launchd) or without a passcode, the result is `ErrUnavailable`. Cancelling or failing is an ordinary refusal.
- **Other platforms** (`presence_other.go`) always return `ErrUnavailable`. Callers then fail closed, or fall back as described below.

## `confirmHuman` (`cmd/gate.go`)

The CLI's single gate for sensitive actions:

1. Show the presence dialog. Success, or any refusal *other than* "unavailable", is final.
2. If the dialog is unavailable and **a PIN is set**, ask for the PIN again, **never accepting the session ticket**. With `pinFollows`, the caller is about to ask for the PIN itself anyway, so `confirmHuman` leaves that prompt to the caller.
3. If neither is available, refuse and suggest `nokey auth setup`.

Callers:

- `exec`: for `approval: always`, or when there is no policy;
- `export`;
- `policy approve`;
- `proxy start`;
- `keychain backup`;
- `rename`;
- `delete`, `set` and `import` when they replace or remove *existing* secrets (`confirmSecretChange` in `cmd/secret_gate.go`). Policy rules match names and commands trust the values behind them, so changing a stored secret needs a human.

The MCP server uses the presence dialog *after* elicitation, with **no PIN fallback** ([Approvals and session tokens](approval-and-tokens.md)).

## PIN (`internal/auth`)

**Setup** (`nokey auth setup`):

- Requires an interactive terminal and a PIN of at least 4 characters, entered twice.
- The PIN is hashed with **Argon2id** (time 3, 64 MiB, 2 threads, 32-byte key, 16-byte salt) into a self-describing string.
- The hash is stored in the keyring as `__nokey_pin_hash__`.
- `auth change` checks the old PIN first. It is also the only path that accepts a legacy SHA-256 hash, so that hash can be upgraded. Everything else refuses it.
- `auth disable` asks for the current PIN.

**Verification** (`Authenticate`):

- Refuses outright unless **stdin is a TTY**.
- Reads the PIN without echo and zeros it after use.
- Compares in constant time.
- Bounds the Argon2id parameters accepted from a stored hash (time ≤ 16, memory ≤ 1 GiB, threads ≤ 16, minimum salt and key lengths). The hash comes from the keyring, and out-of-range values would panic or allocate without limit.

**Backoff** (`backoff.go`):

- Failures are counted in the keyring entry `__nokey_auth_failures__`, so the count is shared across processes. Keyring stores register themselves through `SetBackoffStore`.
- After 3 failures, each new attempt must wait `2^(failures-3)` seconds, capped at 60s, since the last failure.
- Success clears the counter.

**Which method applies** (`resolveAuthMethod` in `cmd/exec.go`): a stored PIN or `require_auth` forces `pin`, whatever `auth.default_method` says. `--auth-method` may add factors but never remove one. PIN-gated reads use `store.AuthenticatedGetAll` and `AuthenticatedGetMany`.

## PIN session tickets (`internal/session`)

After a successful PIN entry, `nokey exec` writes a sudo-style ticket so later runs inside `auth.session_ttl` skip the prompt. The TTL defaults to 15m and is capped at 8h.

- **File**: `~/.config/nokey/session_ticket`, mode 0600, written to a temp file and renamed, so an existing file or symlink is replaced rather than written through.
- **Content**: a random 32-byte token, plus `HMAC-SHA256(key = PIN hash, token ‖ issued-unix-seconds)`.
- **Expiry** comes from the file's **mtime**, which is bound into the HMAC. `touch`-ing the file invalidates the ticket instead of extending it.
- **Valid** rejects:
  - a ticket that isn't a regular file, or is a symlink or FIFO (checked with `Lstat`);
  - a file swapped between `Lstat` and `open` (`os.SameFile`);
  - group or world permission bits, on non-Windows systems;
  - an mtime more than 60s in the future;
  - a ticket older than the TTL, which is deleted.

  It reads at most 1 KiB of the file.
- Changing the PIN changes the HMAC key, so every existing ticket stops working.

Only some paths accept the ticket. `exec` passes `useSession=true`. `export` passes `false`. `confirmHuman` never accepts it.

## Tests

- `internal/auth/auth_test.go` and `backoff_test.go` cover hashing, parameter bounds and backoff timing (`nowFn`).
- `internal/session/session_test.go` covers mtime tampering, symlinks and permissions.
- `cmd/secret_gate_test.go` and `cmd/auth_test.go` cover the commands.
- Tests replace `presenceConfirmFn` through `withPresence` ([Testing](../operations/testing.md)).

Related: [Approvals and session tokens](approval-and-tokens.md), [macOS dedicated keychain and Touch ID](../architecture/macos-keychain.md), [Configuration](../reference/configuration.md).
