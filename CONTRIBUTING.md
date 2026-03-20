# Contributing to nokey

Thanks for your interest in contributing to nokey! This guide will help you get started.

## Development Setup

**Requirements:** Go 1.24+

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

## Reporting Bugs

Use the [bug report template](https://github.com/nokey-ai/nokey/issues/new?template=bug_report.md) to file issues.

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
