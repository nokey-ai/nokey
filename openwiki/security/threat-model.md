---
type: security
title: Threat model
description: What nokey defends and what it doesn't. Covers the actors (the person at the machine, an AI agent or other program running as the same user, the child process), the trust boundaries the code enforces (keyring-held state over writable files, human-only confirmation, approved policy digests, redaction and the proxy), the documented gaps, and the security reporting policy.
tags: [security, threat-model, trust-boundaries, redaction, memory]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-182018713d640f72e4f6c64f
    resource: repo://internal/policy/policy.go
  - id: openwiki-source-d3fd22a0e56438f2a7ed54aa
    resource: repo://internal/sensitive/clear.go
  - id: openwiki-source-23775c3de52f3ab95a13cb8b
    resource: repo://README.md
  - id: openwiki-source-3a44815832a872f4778f822b
    resource: repo://SECURITY.md
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Threat model

nokey lets AI coding assistants and other tools **use** credentials without the credentials appearing in the assistant's context, the repository or shell history. The README's "Threat Model" section and `SECURITY.md` are the user-facing statements. This page maps them onto the mechanisms in the code.

## Actors

| Actor | Trust |
|---|---|
| **Person at the machine** | Trusted. The only party that can approve: the OS presence dialog, a PIN at a real TTY, `nokey policy approve`. |
| **Agent or other program running as the same user** | *Not* trusted to approve anything. It can run `nokey`, answer stdin, fake a TTY, answer its own MCP elicitation, and rewrite files under `~/.config/nokey`. |
| **Child process** started by `exec` | Trusted with the secrets it is given. nokey is **not a sandbox**: it can read and send out whatever it receives. |
| **OS keyring** | The storage the design relies on. nokey's own control state lives there, not in files. |

## Boundaries the code enforces

1. **Approval only from a human.** `confirmHuman` accepts the OS presence dialog, or a fresh PIN when no dialog is available. A stdin y/N prompt never counts. MCP approvals need elicitation **and** the presence dialog. See [Human presence, PIN and sessions](human-presence-and-pin.md) and [Approvals and session tokens](approval-and-tokens.md).
2. **Files can only add gates.** Anyone running as the user can rewrite `config.yaml` and `policies.yaml`, so:
   - config cannot switch off a stored PIN, and `cli_enforce_policy` is ignored;
   - a policy applies only when its SHA-256 matches the digest a human approved, which is stored in the keyring;
   - with no policy, every secret access needs human approval.

   See [Configuration](../reference/configuration.md#config-can-only-add-gates) and [Policy file](policies.md).
3. **Control state lives in the keyring** under `__nokey_`. That covers the PIN hash, the failure counter, the policy digest, the audit key and the proxy CA key. Public `Set`, `Get` and `Delete` refuse that prefix, so `nokey` itself can't be used to replace or remove them. See [Secret storage](../architecture/secret-storage.md).
4. **Least exposure per call.**
   - `--only`/`--except` limit what is injected.
   - MCP reads only the values that pass filtering, policy and approval.
   - `exec_with_secrets` keeps secrets out of the environment.
   - Reserved environment names (loaders, proxies, CA bundles) can't be set or used as secret names.
5. **Output redaction** of values and common encodings, including every value the MCP session has read so far. Values under 4 bytes are refused for MCP. See [Command execution and output redaction](../architecture/exec-and-redaction.md).
6. **Proxy mode** gives the secret to the network request, never to the child. Its protections:
   - loopback only, with a per-run credential;
   - HTTPS-only injection;
   - SNI and Host pinning;
   - a name-constrained CA whose key is kept in the keyring.

   See [Secret-injecting proxy](../architecture/proxy.md).
7. **Tamper-evident audit.** An encrypted HMAC chain plus a checkpoint reveals truncated, appended or edited entries. See [Audit log](audit-log.md).

## Not protected (by design or known limitation)

- **Malicious code given secrets.** A child process that receives a secret through its environment or arguments can send it out. Mitigation: `--only`, `exec_with_secrets`, proxy mode, and running only trusted code.
- **Getting around redaction.** Only the exact value and a fixed set of transforms are matched: reversed, base64 variants including offset forms, URL, JSON, hex. Other encodings, compression, encryption, or output split up or printed one character at a time all get through. Redaction is defence in depth.
- **Memory.** Secrets sit in process memory while in use. `internal/sensitive` zeroes what it can reach, but documents what it can't:
  - copies made at `execve`;
  - `fmt` intermediates;
  - copies inside libraries;
  - freed pages;
  - strings under 8 bytes;
  - read-only strings.
- **A compromised OS account or keyring.** A process running as the user can delete `__nokey_` items with the OS's own tools. On macOS, `security delete-generic-password` works on an unlocked dedicated keychain without a prompt. The README explains:
  - Deleting the policy digest and the file leaves *no* policy, which means more prompts, not fewer.
  - Deleting the PIN hash **does** remove the PIN from CLI `approval: never` rules.
- **Platforms without a presence dialog.** The presence dialog is macOS-only. Elsewhere the CLI gates fall back to the PIN, and MCP approvals, which have no PIN fallback, fail closed.

## Reporting

`SECURITY.md`: report privately to `security@nokey.ai`, not in a public issue. Acknowledgement within 48h, initial assessment within 5 business days, coordinated disclosure.

In scope:

- keyring interactions;
- PIN hashing and authentication;
- cryptography (Argon2id, secretbox);
- redaction;
- MCP and proxy injection.

Out of scope:

- upstream dependency bugs;
- social engineering;
- local denial of service.

Related: [Architecture overview](../architecture/overview.md), [Policy file](policies.md), [Command execution and output redaction](../architecture/exec-and-redaction.md), [Secret-injecting proxy](../architecture/proxy.md).
