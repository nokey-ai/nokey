# Contributing to nokey

Thanks for your interest in contributing to nokey! This guide will help you get started.

## Development Setup

**Requirements:** Go 1.26+

```bash
# Fork and clone
git clone https://github.com/<your-username>/nokey.git
cd nokey

# Install dependencies
go mod download

# Build
make build

# Run tests
make test

# Run linter
make lint
```

## Code Style

- Run `golangci-lint run` before submitting (or `make lint`)
- Run `go vet ./...` to catch common issues
- Add tests for new functionality — aim to maintain or improve coverage
- Follow existing patterns in the codebase

## Pull Request Process

1. **Branch naming**: `feature/description`, `fix/description`, or `docs/description`
2. **Commit messages**: Use imperative mood, explain the "why" not the "what"
   - Good: `Add OAuth token refresh on expiry`
   - Bad: `Updated oauth.go with refresh logic`
3. **Tests required**: All PRs must include tests and pass `make test`
4. **Lint clean**: `make lint` must pass with no issues
5. **One concern per PR**: Keep PRs focused on a single change

## Areas for Contribution

- OAuth provider implementations (Google, Azure AD, etc.)
- Additional audit export formats
- Integration examples with other AI coding tools
- Documentation improvements
- Bug fixes and performance improvements

## Release Signing (maintainers)

The release workflow signs the macOS binaries with the certificate in the
`MACOS_SIGN_P12` secret, so the keychain keeps trusting nokey across
upgrades. A self-signed certificate is enough; what matters is using the
same one for every release. To create one, or to rotate it:

```bash
cat > sign.cnf <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = nokey release signing
[ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
CNF
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -keyout sign.key -out sign.crt -config sign.cnf -extensions ext
# -legacy: macOS `security import` can't read OpenSSL 3's default PKCS#12 encryption.
openssl pkcs12 -export -legacy -inkey sign.key -in sign.crt -out sign.p12
base64 -i sign.p12 | gh secret set MACOS_SIGN_P12 -R nokey-ai/nokey
gh secret set MACOS_SIGN_P12_PASSWORD -R nokey-ai/nokey
```

Then delete the working files. The secrets are the only copy, and that's
fine: if the certificate is lost or needs changing, create a new one the
same way. The only cost is one more round of keychain prompts for users
after the next release. Without the secret, releases fall back to ad-hoc
signing.

## Reporting Bugs

Use the [bug report template](https://github.com/nokey-ai/nokey/issues/new?template=bug_report.md) to file issues.

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
