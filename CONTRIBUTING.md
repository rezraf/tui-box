# Contributing to TuiBox

TuiBox accepts focused bug fixes, tests, documentation improvements, and changes aligned with the current architecture. Discuss broad feature or trust-boundary changes in an issue before implementation.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Requirements:

- Go `1.25` as declared by `go.mod`;
- POSIX `sh` for installer and packaging checks;
- Linux or macOS for platform-specific behavior;
- optional sing-box `1.13.14` integration access through the existing test harness.

Clone the repository, then run:

```sh
go mod download
go test ./...
go vet ./...
go build ./cmd/tuibox ./cmd/tuiboxd
```

Ordinary tests must remain offline. Tests that need HTTP use local test servers. The pinned-core integration test runs only when explicitly enabled by its existing environment gate.

## Change guidelines

- Keep the unprivileged client and root daemon separated.
- Never move subscription fetching, state storage, credential storage, telemetry, or updates into CLI help/version/completion paths.
- Treat subscription documents, endpoint fields, RPC input, archive contents, filesystem paths, and environment values as untrusted.
- Do not pass user-controlled strings through a shell.
- Preserve stable public errors; do not expose raw provider, RPC, or core output.
- Do not log or commit subscription URLs, credentials, imported documents, endpoint structs, RPC payloads, or sing-box output.
- Keep functions small and changes surgical. Add regression coverage for failures and boundary conditions.
- Update public documentation when commands, controls, formats, paths, security properties, telemetry, or release behavior changes.

## Tests and validation

Before opening a pull request, run:

```sh
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/tuibox ./cmd/tuiboxd
sh -n install.sh uninstall.sh scripts/cross-build.sh scripts/packaging_test.sh
./scripts/packaging_test.sh
./scripts/cross-build.sh
go run ./cmd/tuibox --help
git diff --check
```

For documentation changes, also run:

```sh
go test ./scripts -run 'TestDocumentation'
git grep -nE 'T[O]DO|CHANGE[M]E|YOU[R]_' -- ':!go.sum'
```

The documentation tests are network-free. They exercise CLI help, verify required local links/paths, check the canonical GPL text and SPDX identifier, and scan public documentation for placeholders and likely secrets.

## Pull requests

- Keep one concern per pull request.
- Explain the failure mode or user outcome, not only the implementation.
- List exact verification commands and results.
- Add tests before or with the fix.
- Call out security-boundary, privilege, data-format, or compatibility changes.
- Do not include generated release artifacts, local caches, credentials, or machine-specific paths.

## Release process

Maintainer release procedure implemented by the repository:

1. Ensure CI passes on the intended release revision.
2. Create a stable semantic tag matching `v<major>.<minor>.<patch>` on a commit reachable from `main`. Its version must be greater than every published stable release.
3. Push the tag. Release runs are serialized, and the workflow rejects malformed, non-mainline, or non-monotonic tags before building.
4. The workflow runs shell syntax checks and offline repository tests.
5. GoReleaser builds `tuibox` and `tuiboxd` for Linux/macOS on amd64/arm64, creates four `.tar.gz` archives plus `checksums.txt`, and uploads them to a draft GitHub Release. A retry replaces the same tag's existing draft.
6. The workflow creates build-provenance attestations for every archive listed in `dist/checksums.txt` and for `checksums.txt` itself.
7. After every attestation succeeds, the final workflow step publishes the still-draft release and marks it latest in one API update.

A failed run leaves no public unattested release; any created release remains a hidden draft. The workflow does not sign release artifacts. Do not describe checksums or provenance attestations as artifact signatures. GitHub repository settings, branch protection, and private vulnerability reporting are operational settings outside the files in this repository and must be verified separately.

## License

Contributions are accepted under the repository's [GPL-3.0-only license](LICENSE).
