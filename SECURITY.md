# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in nokey, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@nokey.ai**

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix timeline**: depends on severity, typically within 30 days for critical issues

## Scope

The following are in scope:
- Secret storage and retrieval (keyring interactions)
- PIN hashing and authentication
- Cryptographic operations (Argon2id PIN hashing, NaCl secretbox audit encryption)
- Output redaction
- MCP server and proxy secret injection

The following are out of scope:
- Vulnerabilities in upstream dependencies (report to the respective project)
- Social engineering attacks
- Denial of service against local CLI usage

## Disclosure Policy

We follow coordinated disclosure. We will:
1. Confirm the vulnerability and determine its impact
2. Develop and test a fix
3. Release a patched version
4. Credit the reporter (unless anonymity is requested)

We ask that you give us reasonable time to address the issue before public disclosure.
