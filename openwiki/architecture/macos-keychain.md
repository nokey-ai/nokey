---
type: architecture
title: macOS dedicated keychain and Touch ID
description: macOS-only storage features. Covers the opt-in dedicated keychain file, Touch ID unlock through byteness/keyring, partition-list "build trust" that stops per-upgrade password prompts, lock settings, and the keychain migrate, to-dedicated, from-dedicated, backup, restore and prune-orphan commands with sealed backups.
tags: [macos, keychain, touch-id, backup, migration, keyring]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-273e7e0ce12dc59ae61d08f2
    resource: repo://cmd/keychain.go
  - id: openwiki-source-d88dd56dbc4620bda4c35f1c
    resource: repo://cmd/root.go
  - id: openwiki-source-b74ff260b91808b6d97df616
    resource: repo://internal/backup/backup.go
  - id: openwiki-source-a8910515ddd14810ad43f5c1
    resource: repo://internal/config/config.go
  - id: openwiki-source-343caf02f01b46234c2c32bf
    resource: repo://internal/keyring/buildtrust_darwin.go
  - id: openwiki-source-ce028d6e565b1f92f378aaac
    resource: repo://internal/keyring/keychain_settings_darwin.go
  - id: openwiki-source-6365c033f8e52bc5829e5683
    resource: repo://internal/keyring/keychain_status_darwin.go
  - id: openwiki-source-ac1afc23925ae59919b2f8be
    resource: repo://internal/keyring/keyring.go
  - id: openwiki-source-15e8e3c0c5f7ef2fd6e7919f
    resource: repo://internal/keyring/touchid_item_darwin.go
  - id: openwiki-source-4c10496d911f24a633575d3a
    resource: repo://internal/keyring/touchid_item.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# macOS dedicated keychain and Touch ID

On macOS, nokey stores secrets in the login keychain by default. Config can switch it to a **dedicated keychain**, a separate file `~/Library/Keychains/<name>.keychain-db`. That file unlocks with Touch ID and locks on its own. This page covers the macOS-only code in `internal/keyring/*_darwin.go`, the `nokey keychain` commands in `cmd/keychain.go`, and the sealed backups in `internal/backup` that make migration safe. For the cross-platform keyring wrapper, see [Secret storage](secret-storage.md).

## Turning it on

`config.yaml` holds these settings (`internal/config/config.go`):

```yaml
keyring:
  dedicated: true      # opt-in
  name: nokey          # optional; defaults to "nokey" when dedicated is true
auth:
  use_biometrics: true             # default true on macOS
  biometrics_only_when_locked: false
```

`getKeyring` (`cmd/root.go`) resolves the name and passes `dedicated` and `keychainName` to `keyring.New`. Setting `KeychainName` in the `byteness/keyring` config is what switches the library to the dedicated file. It is also the only mode where the library actually honours `UseBiometrics`; access to the login keychain ignores it. `DedicatedKeychainPath` returns `""` on other operating systems, so every dedicated-keychain path is inert there.

With `biometrics_only_when_locked`, `useBiometrics` checks `KeychainUnlocked`, a cgo call to `SecKeychainGetStatus` that never prompts. If the dedicated keychain is already unlocked, the process opens it without asking for Touch ID.

## Touch ID item

For Touch ID unlock, `byteness/keyring` keeps the dedicated keychain's passphrase in the **login** keychain:

| Field | Value |
|---|---|
| Service | nokey service name |
| Account | `com.nokey.biometrics` (`TouchIDAccount`) |
| Label | `Passphrase for <name>.keychain` |

macOS identifies an item by service and account alone. So an item left behind by a *different* dedicated keychain can't be found by the library, because its label differs, and can't be replaced either. First-time setup then fails with `errSecDuplicateItem`.

`FindStaleTouchIDItem` runs `security find-generic-password`, which reads attributes only and never prompts, to detect that case. `keychain to-dedicated` refuses to start when it finds one and prints the `security delete-generic-password` command that removes it. `keychain prune-orphan` removes the leftover item after someone deletes the dedicated keychain file by hand. It supports `--dry-run`.

## Build trust (partition lists)

Each keychain item records the code hashes of the builds allowed to read it (its partition list). A certificate-signed binary that Apple did not sign is identified by its cdhash. Without help, every nokey upgrade would make macOS ask for the keychain password once per item.

`buildtrust_darwin.go` (cgo, Security.framework) works around this:

1. `runningBuildPartition` reads the running binary's cdhash and whether it is certificate-signed. Ad-hoc builds are skipped.
2. `trustBuild` finds the items whose partition list lacks `cdhash:<hash>`.
3. If any are missing, it reads the Touch ID passphrase from the login keychain. It then calls the **private** `SecKeychainItemSetAccessWithPassword`, the same call `/usr/bin/security set-generic-password-partition-list` uses, to add the partition.

The public API would ask the user to confirm each change. Without Touch ID set up there is no stored passphrase, and nokey quietly falls back to macOS prompting per item. The passphrase is copied into C memory and zeroed after use.

Only the partition list changes. Each item's trusted-application ACL still requires nokey's signing certificate, so adding a binary signed by anyone else gives it nothing. `keyring.New` attaches this as `Store.trustBuild`, which a `sync.Once` runs before the first secret read in a dedicated-keychain store.

## Lock policy

`ApplyKeychainSettings` runs `security set-keychain-settings -l -u -t 300`. The keychain then locks on sleep and after 5 minutes idle. A fresh dedicated keychain has no such defaults and would otherwise stay unlocked once opened. `to-dedicated` applies these settings after copying secrets.

## Commands (`nokey keychain …`)

| Command | What it does |
|---|---|
| `migrate` | Re-creates login-keychain items with Touch ID and a trusted-app ACL (for items from before biometrics), then writes a "migrated" sentinel. `--dry-run`, `--yes`. Prints a message and does nothing off macOS. |
| `to-dedicated` | Copies every secret from the login keychain into the configured dedicated keychain. |
| `from-dedicated` | Reverses `to-dedicated`. Refuses unless the migration sentinel is present. Leaves the dedicated file on disk and prints the `security delete-keychain` command. |
| `backup --out FILE` | Asks for human confirmation (`confirmHuman`), loads every secret, and writes a sealed blob. |
| `restore --in FILE` | Decrypts a backup and writes the missing secrets. `--dry-run`. |
| `prune-orphan` | Removes a leftover Touch ID item (see above). |

`to-dedicated` steps, in order:

1. Require `keyring.dedicated`.
2. Confirm with y/N.
3. Look for a leftover Touch ID item.
4. Load the source secrets (PIN-gated), dropping internal `__nokey_` keys.
5. Write a sealed backup to `<config>/backups/v0.5.0-pre-migration-<UTC>.enc`, unless `--no-backup` is given.
6. Sort each secret against the destination: new, already present, or conflicting. **Abort without writing anything if any value conflicts.**
7. Write the new secrets.
8. Re-read and compare each written value.
9. Apply the lock settings.
10. Only then write the `__nokey_migrated_to_dedicated__` sentinel.

Login-keychain entries are left in place.

Restore uses the same rules: any conflicting value aborts the whole restore. Backup keys starting with `__nokey_` are skipped, so a crafted backup can't overwrite the PIN hash or the sentinels. Backup and restore passphrases come from a terminal prompt or `--password-stdin`, never from argv, because other processes can read argv through `ps`. An empty passphrase is refused.

## Sealed backups (`internal/backup`)

The blob layout is `salt(16) ‖ nonce(24) ‖ secretbox ciphertext`. The key comes from Argon2id with the same parameters as the PIN hash: time 3, 64 MiB, 2 threads, 32-byte key. The ciphertext is NaCl secretbox (XSalsa20-Poly1305), the same primitive the audit log uses. The payload is JSON `{version, timestamp, secrets}` with `CurrentVersion = 1`, and restore rejects any other version.

`Decrypt` returns one error for a truncated blob and another for an authentication failure (wrong password or tampering). `Write` stages the blob in a temp file, sets mode 0600, fsyncs and renames it into place, creating the directory with mode 0700.

## Tests

- `internal/keyring/buildtrust_darwin_test.go` uses `readWithoutPrompt` to watch partition lists take effect.
- `keychain_settings_darwin_test.go` and `keychain_status_darwin_test.go` cover the lock settings and status checks.
- `internal/backup/backup_test.go` covers backups, and `backup_fuzz_test.go` fuzzes `Decrypt`.
- `cmd/keychain_test.go` stubs `applyKeychainSettingsFn`, `findStaleTouchIDItemFn` and `openKeyringForFn`.

Related: [Secret storage](secret-storage.md), [Human presence, PIN and sessions](../security/human-presence-and-pin.md), [Configuration](../reference/configuration.md).
