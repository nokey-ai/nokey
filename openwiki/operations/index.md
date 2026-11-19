# Files

- [Build, CI and release](build-test-release.md) - How nokey is built, checked and shipped. Covers Makefile targets (including `make check`), the CI jobs (race tests on Linux and macOS, lint, gofmt, tidy, Windows vet, govulncheck), the tag-driven GoReleaser release with macOS codesigning and a Homebrew cask, and how `nokey update` verifies and replaces the binary.
- [Testing](testing.md) - How nokey's tests are laid out and kept hermetic. Covers the cmd package's TestMain stubs for the keyring and presence dialog, the in-memory keyring and helper functions, function-variable seams, MCP JSON-RPC integration tests, fuzz targets, platform-tagged tests, and the lint rules.
