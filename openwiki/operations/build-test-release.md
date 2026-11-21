---
type: operations
title: Build, CI and release
description: How nokey is built, checked and shipped. Covers Makefile targets (including `make check`), the CI jobs (race tests on Linux and macOS, lint, gofmt, tidy, Windows vet, govulncheck), the tag-driven GoReleaser release with macOS codesigning and a Homebrew cask, and how `nokey update` verifies and replaces the binary.
tags: [build, ci, release, goreleaser, codesign, homebrew, update]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-164e2da859b5277df81c7d94
    resource: repo://.github/workflows/ci.yml
  - id: openwiki-source-4d1d392666be6dfdd7a91a2e
    resource: repo://.github/workflows/release.yml
  - id: openwiki-source-712642f5bc1b982bbec2b6da
    resource: repo://.goreleaser.yaml
  - id: openwiki-source-4bc42f15b878dcc5cc01031e
    resource: repo://cmd/update.go
  - id: openwiki-source-828d325fa34da8ff9b108c1a
    resource: repo://internal/update/update.go
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Build, CI and release

nokey is a Go module, `github.com/nokey-ai/nokey`, using Go 1.26. Version, commit and date are set into `internal/version` through `-ldflags -X` by both the Makefile and GoReleaser.

## Makefile

| Target | What it does |
|---|---|
| `build` | `go build` → `./nokey`. On macOS it then **ad-hoc codesigns** the binary (`codesign -s -`), which keychain access with Touch ID needs. |
| `install` | `go install`, plus the same ad-hoc signing on macOS. |
| `test` | `go test ./...` |
| `vet` / `lint` / `fmt` | `go vet ./...`, `golangci-lint run`, `gofmt -w .` |
| `check` | `test` + `vet` + `lint`. This is the local stand-in for CI. |
| `coverage` | Coverage profile and per-function report. |
| `release` | `goreleaser release --clean`. Releases normally run in CI, not locally. |

An ad-hoc signature identifies the binary by its hash, so every rebuild loses the login keychain's trust and macOS prompts again. The dedicated keychain and partition-list build trust exist to deal with that ([macOS dedicated keychain](../architecture/macos-keychain.md)).

The lint configuration lives in `.golangci.yml` (golangci-lint v2). See [Testing](testing.md).

## CI (`.github/workflows/ci.yml`)

CI runs on pushes and PRs to `main`, with read-only permissions.

- **build**, on ubuntu-latest and macos-latest: `go build ./...`, then `go test ./... -race`, then `go vet ./...`. `-race` matters because the proxy, the MCP server and the PTY reader all run concurrent goroutines. Tests stub the keyring, so the macOS job never blocks on a keychain prompt.
- **lint**, on ubuntu:
  - golangci-lint v2.15.0, installed with `go install`, with retries;
  - `gofmt -l`;
  - `go mod tidy -diff`;
  - `GOOS=windows go vet ./...`. There is no Windows runner, and the Windows build is CGO-free, so this cross-check catches breakage in the Windows-tagged files.
- **vulncheck**: govulncheck v1.7.0, which fails only on vulnerabilities the code actually reaches.

Third-party tools are installed with `go install` rather than through marketplace actions. The org allows only GitHub-owned or verified actions, and a rejected action fails the whole workflow at startup.

## Release (`.github/workflows/release.yml` + `.goreleaser.yaml`)

The release workflow runs on a `v*` tag push. `workflow_dispatch` runs a **dry run** (`--snapshot`) that builds every target and publishes nothing. That matters because tags are immutable here, so a failed release costs a version number.

1. **Gates.** `test` (race on Linux and macOS, plus vet) and `vulncheck` run first, so a tag cut from a commit CI never saw is still checked.
2. **Release job on macos-latest** (only this job has `contents: write`):
   - Install Linux cross-toolchains from the `messense/macos-cross-toolchains` tap. The tap must be explicitly trusted (`brew trust`).
   - Import the code-signing certificate from the `MACOS_SIGN_P12` secret into a temporary keychain, and export `NOKEY_CODESIGN_IDENTITY`. **Without the secret, darwin builds fall back to ad-hoc signing**, with a warning.
   - Create a GitHub App token for `nokey-ai/homebrew-tap`.
   - Install GoReleaser v2.18.0 with `GOTOOLCHAIN=auto` for that step only, then run it.

GoReleaser builds:

| Target | CGO | Notes |
|---|---|---|
| darwin amd64 and arm64 | on (Apple clang) | A post-build hook runs `codesign -f -s "$NOKEY_CODESIGN_IDENTITY"` (or `-` for ad-hoc) with `--identifier com.nokey-ai.nokey`. |
| linux amd64 and arm64 | on (messense cross-gcc) | |
| windows amd64 and arm64 | off | |

CGO is required on darwin and Linux because `byteness/keyring` pulls in `onepassword-sdk-go`, whose `!cgo && (darwin || linux)` build tag deliberately breaks the build.

Signing with a stable certificate makes the keychain's designated requirement "identifier + certificate", which stays the same from one release to the next. An ad-hoc signature's requirement is the binary hash, which changes with every build.

Outputs:

- `tar.gz` archives (`zip` on Windows) named `nokey_<version>_<os>_<arch>`, plus `checksums.txt`;
- a **Homebrew cask** in `nokey-ai/homebrew-tap`, committed as the GitHub App because the tap only accepts signed commits. The cask's postflight step removes the macOS quarantine attribute.

Maintainer steps for creating the signing certificate are in `CONTRIBUTING.md` ("Release Signing"). Release notes go in `CHANGELOG.md` (Keep a Changelog format).

## Self-update (`nokey update`, `internal/update`)

- `nokey update --check` only reports whether a newer release exists. `--force` replaces a development build or reinstalls the current release.
- A Homebrew-managed binary is upgraded with `brew upgrade --cask nokey-ai/tap/nokey`, so brew keeps track of the installed version.
- Otherwise nokey fetches the latest non-prerelease release from the GitHub API for `nokey-ai/nokey`. It downloads the archive for the platform (up to 200 MiB) and **checks its SHA-256 against `checksums.txt`**. A missing entry or a mismatch is an error. It then extracts the binary.
- `update.Replace` writes the new binary next to the old one and renames it into place, so a failure leaves the old binary intact. On Windows, which won't overwrite a running executable, the old binary is first moved to `.old`.

Related: [Testing](testing.md), [Quickstart](../quickstart.md).
