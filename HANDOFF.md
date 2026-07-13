# TuiBox v0.1 — Paused Work Handoff

Security tasks #98 through #101 completed on 2026-07-14. Task #102 is in progress; the separate cache-cleanup item remains pending.

## Resume location

- Repository root: the current checkout reported by `git rev-parse --show-toplevel`
- Branch: `feature/v0.1`
- Last committed HEAD: `b45af14`
- Historical implementation handoff: `.claude/handoffs/2026-07-13-182450-tuibox-v01-continuation.md`
- Product specification: `.agent/SPECS/tuibox-v0.1.md`
- Remaining checklist: `.agent/TODOS/tuibox-v0.1.md`
- Implementation plan: `docs/plans/2026-07-13-tuibox-v0.1.md`

Confirm the branch and checkout before resuming with `git status --short --branch`.

## Current state

Tasks 1–9 are complete in the product checklist. Task 10 stays unchecked until the final release-source and repository verification gate passes. Their implementation plus security hardening through task #101 remain in the current uncommitted working tree together with tests and project-state updates. No commit or push was performed.

Task #102 is in progress. The separate cache-cleanup item remains incomplete.

## Task 9 completed

Created or completed the English public documentation and governance surface:

- `README.md`
- canonical GPL v3 text in `LICENSE`, documented as SPDX `GPL-3.0-only`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `docs/architecture.md`
- `docs/security-model.md`
- `docs/telemetry.md`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/config.yml`
- `.github/pull_request_template.md`

The documentation was derived from the implemented CLI help, installers, updater, systemd/launchd definitions, TUI bindings, user/system data paths, parser/domain models, RPC/core privilege boundary, telemetry package and composition, and CI/release workflow.

Documented implementation facts include:

- Linux/macOS on amd64/arm64 only;
- URI list, whole-document Base64, Clash YAML `proxies`, and sing-box JSON `outbounds`;
- VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC;
- exact TUI keys and subscription input behavior;
- TUN/Proxy and Global/Rule/Direct behavior;
- user state and fallback-secret paths and permissions;
- normalized endpoint credentials are cached in restricted `state.json`, while subscription source URLs use the OS credential backend or fallback `secrets.json`;
- root daemon peer authorization and generated-config/core execution boundary;
- telemetry defaults off, has a closed schema, and sends nothing in v0.1 because no endpoint or sender is wired;
- installer/updater checksum behavior, no artifact signature verification, no core/service update, and no automatic daemon restart;
- release workflow checksums and build-provenance attestation without describing them as artifact signatures;
- current limitations and troubleshooting paths.

Added `scripts/docs_test.go` with network-free checks for:

- actual root and subcommand help paths;
- README command names;
- required documentation/governance files;
- local Markdown links and path containment;
- canonical GPL-3.0 license content and SPDX identifier;
- public-document placeholder patterns;
- likely secret patterns.

## Task 9 verification

Passed:

```text
go run ./cmd/tuibox --help
all 23 documented group/leaf/completion subcommand help paths via go run
sh -n install.sh uninstall.sh
go test ./scripts -run 'TestDocumentation' -count=1
go test ./...
placeholder scan excluding intentional planning/tracker/validator references and go.sum
high-confidence private-key/cloud-token secret-pattern scan excluding go.sum
git diff --check
```

The first attempted subcommand-help loop passed each command path as one shell argument under zsh and failed with `invalid command usage`; the loop was corrected to pass fixed argv elements. All actual help paths then passed.

## Task 10 verification history

The adversarial review fixed stale TUI manual selection, updater helper trust before `sudo`, installer/uninstaller ancestor and symlink trust, uninstall preservation of unrelated files, and release workflow credential/tag controls. Regression tests cover each production behavior change. Task 10 remains unchecked until the current final gate passes.

Earlier local verification passed Task 7–9 focused tests, installer lifecycle tests, documentation/workflow tests, `go test ./...`, `go test -race ./...`, `go vet ./...`, both binary builds, all four cross-builds, shell syntax, YAML parsing, pinned sing-box config validation, formatting, secret/placeholder scans, and `git diff --check`. These results are historical evidence, not a substitute for the final task #102 gate.

Remote checks confirmed every pinned action SHA/tag and all four sing-box 1.13.14 asset digests. The public GitHub repository currently has no default branch, no configured environment, and private vulnerability reporting disabled, so branch/tag protection, release publication, and attestation emission cannot be validated until repository content is pushed and settings are configured.

## Security task #98 completed

The uninstaller now completes all path, ownership, mode, symlink, overlap, ACL, service-manager, and identity preflight before stopping a service or deleting files. It pins filesystem identities across service shutdown, rejects path replacement, ignores stop errors only after verified systemd not-found or launchd not-loaded states, and requires the service to be inactive before removal.

Normal uninstall preserves user state and unrelated files. Purge removes only exact user state entries and 32-hex TuiBox runtime configs without shell glob expansion or symlink following. User-file deletion runs with the selected user identity rather than elevated privileges. The script also ignores untrusted `PATH` command overrides.

Regression coverage in `scripts/packaging_test.sh` includes missing `HOME`, relative and overlapping paths, unsafe/symlink paths, Linux and macOS stop outcomes, path replacement during shutdown, no-follow purge behavior, state preservation, untrusted `PATH`, and writable macOS ACLs.

Passed after the final changes: all focused uninstall cases, the full packaging harness under both `/bin/sh` and `dash`, `sh -n`, `dash -n`, `go test ./...`, `go test -race ./...`, `go vet ./...`, formatting checks, and whitespace checks. Runtime probes against isolated layouts confirmed normal uninstall, purge allowlisting, genuine stop failure abort, path-replacement abort, launchd not-loaded handling, symlink rejection, ACL rejection, and untrusted `PATH` isolation.

A pre-existing race-only state test exposed that oversized valid snapshots could exhaust the convenience context before size rejection. `internal/state/store.go` now performs encoded-size validation before taking the file lock; the focused state race test and full race suite pass.

## Security task #99 completed

Release publication is now serialized and monotonic. The workflow rejects a stable tag unless it is newer than every published non-draft, non-prerelease stable release. GoReleaser creates or replaces only a draft and never marks it latest. The workflow attests every archive named by `checksums.txt`, attests `checksums.txt` itself, verifies the release is still a draft, then publishes and marks it latest in the final API update. Earlier failures therefore leave no public unattested release.

The default installer now queries paginated GitHub release metadata, selects the highest canonical stable semantic version, and downloads from that tag's immutable release URL. Drafts, prereleases, and malformed versions are ignored. An explicit `TUIBOX_VERSION` skips metadata resolution and remains deterministic. Default resolution requires `jq`; the selector is bundled in release archives.

Strict TDD evidence: the new workflow, GoReleaser, installer, and selector tests first failed on missing concurrency, draft controls, attestations, monotonic validation, metadata resolution, and the absent selector. After implementation, focused release tests, selector shell tests, YAML parsing, actionlint `v1.7.12`, GoReleaser `v2.17.0` configuration validation and snapshot packaging, release archive inspection, installer lifecycle tests under `sh` and `dash`, `go test ./...`, `go test -race ./...`, `go vet ./...`, shell syntax, formatting, and whitespace checks all passed.

## Security tasks #100 and #101 completed

Endpoint identity normalization now parses IP literals with `netip.ParseAddr`, rejects zones, applies `Unmap`, and stores the canonical `String` form before fingerprinting. URI lists, whole-document Base64, Clash, and sing-box therefore collapse equivalent compressed, expanded, zero-padded, uppercase, and IPv4-mapped forms while preserving distinct addresses. Direct legacy fingerprinting uses the same normalization.

Persisted state now receives a bounded token-validation pass before strict struct decoding. Exact duplicate fields and fields that collide under `encoding/json` case folding are rejected recursively across the snapshot, settings, subscriptions, endpoints, TLS, Reality, transport, and all protocol-option structs. Legacy snapshots that omit settings still load. The fallback `secrets.json` map rejects exact decoded-key duplicates while preserving case-distinct keys. Rejected state and fallback-secret files are never replaced or modified.

Strict TDD evidence: the IP tests first failed with two or three endpoints for equivalent addresses and unequal direct fingerprints. The persistence tests first failed with `Update() accepted colliding persisted fields` and `Set() accepted duplicate fallback-secret keys`. After implementation, focused package tests, affected-package race tests, `go test ./...`, `go vet ./...`, formatting checks, and `git diff --check` passed.

## Resume at remaining work

Task #102 is in progress. After its release-source and repository gates pass, the remaining product checklist item is to remove only TuiBox development/verification caches and temporary build/release artifacts without removing unrelated caches.

## Known review points

- Help, version, completion, and usage failures must remain independent of state, secrets, daemon, network, and updater opening.
- `RemoveSubscription` deletes the source URL first, updates state second, and restores the secret with a bounded independent context if state update fails.
- Endpoint IDs are scoped by subscription ID before persistence.
- `UpdateSubscriptions("")` means refresh all subscriptions.
- Direct routing sends a nil endpoint; Global and Rule require a selected endpoint.
- Hysteria2 and TUIC remain unsupported by the TCP latency checker.
- Proxy mode must drop the core process to the authenticated caller UID/GID and remain loopback-only.
- TUN mode intentionally remains under the privileged daemon.
- Never print or log raw subscription URLs, imported documents, endpoint structures, RPC payloads, or sing-box output.
- Ordinary tests must remain offline.
- The updater verifies SHA-256 against the release checksum file but does not verify an independent signature or provenance attestation.
- Telemetry consent is persisted, but no sender is composed and no hosted endpoint is defined.
