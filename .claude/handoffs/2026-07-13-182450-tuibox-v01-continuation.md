# Handoff: Continue TuiBox v0.1 Implementation

## Session Metadata

- Created: 2026-07-13 18:24:50
- Primary repository: `/Users/rezraf/tui-box`
- Active implementation worktree: `/Users/rezraf/.config/superpowers/worktrees/tui-box/feature-v0.1`
- Branch: `feature/v0.1`
- Base branch: `main` at `53aa4d4`
- Current committed HEAD before this handoff commit: `84e80bb`
- Remote: `https://github.com/rezraf/tui-box.git`
- Session duration: one long implementation session

### Recent Commits

- `84e80bb` feat(client): add latency and redaction foundations
- `16a14f5` fix(daemon): harden lifecycle and socket teardown
- `85a2f8e` chore: remove temporary review plan
- `854a653` fix(daemon): harden RPC lifecycle and authorization
- `c2535a5` feat(daemon): add peer-authenticated Unix RPC
- `fe4ac3c` fix(core): harden executable trust and integration tests
- `2fb7d4c` fix(core): use native sing-box stdin token
- `058c063` fix(core): pipe verified configs through stdin
- `e7a380b` fix(core): secure prepared config execution
- `339e226` feat(core): generate and run typed sing-box configs
- `16472bb` fix(secrets): align command store lifecycle
- `5af4915` fix(storage): add context-aware store lifecycles
- `dda8228` fix(storage): harden transactional file access
- `68be7f0` fix(storage): close Task 3 security gaps
- `e665d30` feat(subscription): add secure fetch and storage boundaries
- `637a332` fix(subscription): reject null VMess TLS mode
- `2ef4dd9` fix(subscription): reject ambiguous parser inputs
- `5c56555` fix(subscription): enforce strict parser validation
- `ff27be0` fix(subscription): harden parsing and Reality support
- `13a9eb1` feat(subscription): parse supported subscription formats
- `022ba54` fix(domain): harden validated JSON fields
- `81f486a` fix(domain): constrain VLESS Vision flow
- `8f0afe3` fix(domain): harden endpoint protocol validation
- `f4c5fbb` feat(domain): bootstrap validated domain model
- `53aa4d4` docs: define TuiBox v0.1 architecture

## Handoff Chain

- **Continues from**: None
- **Supersedes**: None

## Current State Summary

TuiBox v0.1 is partially implemented as a Go 1.25 project. Tasks 1–5 are complete, committed, test-covered, and passed separate spec-compliance and code-quality reviews: domain validation, subscription parsers, secure fetch/storage, sing-box config/process management, and peer-authenticated daemon RPC. Task 6 began but was interrupted. Its latency checker, redaction package, and telemetry-consent state field are preserved in commit `84e80bb`; their focused and full tests pass, but they have not received spec or quality review. Application orchestration, telemetry sender, user CLI, TUI, installer/updater, GitHub CI/CD releases, and public OSS documentation remain unfinished.

## Codebase Understanding

## Architecture Overview

TuiBox has three runtime layers:

1. `tuibox`: an unprivileged Go CLI/TUI, not yet created.
2. `tuiboxd`: a root daemon already implemented in `cmd/tuiboxd`. It authenticates Unix peers from kernel credentials and permits only explicit UIDs.
3. `sing-box` 1.13.14: a separate pinned executable. TuiBox generates typed configs and never executes imported provider configs.

The unprivileged client will own subscription URLs, local state, latency checks, telemetry consent, update UX, and TUI. The daemon owns one active connection, TUN privileges, checked config preparation, core process lifecycle, and rollback.

Security boundaries already implemented:

- strict typed endpoint model;
- no arbitrary maps, process arguments, environment, executable paths, or config paths over RPC;
- strict bounded JSON with duplicate-key, case, depth, and message-size checks;
- kernel peer UID/GID authentication and explicit allowlist;
- root/effective-UID-owned executable and runtime checks;
- generated configs passed through sing-box's native `-c stdin` token;
- atomic mode-0600 state/config files inside held `os.Root` directories;
- context-aware file locks, CAS state revisions, and secure lifecycle closure;
- strict opt-in core integration test using verified official release bytes.

## Critical Files

| File | Purpose | Relevance |
|---|---|---|
| `.agent/SPECS/tuibox-v0.1.md` | Frozen product and security requirements | Authoritative scope |
| `.agent/DECISIONS/tuibox-v0.1.md` | Accepted tradeoffs and assumptions | Do not reverse without reason |
| `.agent/TODOS/tuibox-v0.1.md` | Completion checklist | Tasks 6–10 remain |
| `docs/plans/2026-07-13-tuibox-v0.1.md` | Detailed implementation plan | Continue at Task 6 |
| `docs/plans/2026-07-13-tuibox-v0.1-design.md` | Architecture design | Public design rationale |
| `internal/domain/*` | Typed endpoints, protocol options, connection modes | Shared trust boundary |
| `internal/subscription/*` | URI/Base64/Clash/sing-box parsing and HTTPS fetch | Never execute source configs |
| `internal/secrets/*` | Keychain/Secret Service/file fallback | Subscription URLs only here |
| `internal/state/store.go` | Versioned CAS state with atomic persistence | Task 6 adds Settings |
| `internal/core/config.go` | Typed sing-box config generator | Supports six protocols/modes/routes |
| `internal/core/process.go` | Prepared config and sing-box process runner | Privileged execution boundary |
| `internal/rpc/*` | Strict Unix socket protocol/client/server | Client-daemon boundary |
| `internal/daemon/service.go` | Session replacement, rollback, retirement | One active session |
| `cmd/tuiboxd/main.go` | Root daemon entry point | Installer must use its exact flags |
| `scripts/cross-build.sh` | Four-target CGO-free build check | Keep in CI |
| `internal/latency/*` | Partial Task 6 latency implementation | Uncommitted, focused tests pass |
| `internal/redact/*` | Partial Task 6 redaction implementation | Uncommitted, needs review |

## Key Patterns Discovered

- Strict TDD was used: test fails first, minimal implementation, then review.
- Every security-sensitive task received spec review before code-quality review.
- Errors crossing public boundaries are stable and redacted.
- Contexts and sizes are bounded; no indefinite locks or unbounded reads.
- Stores expose `Close` and operations after close fail consistently.
- State mutations use `UpdateContext` or revision/CAS, not stale Load→Save overwrites.
- OS-specific behavior uses build-tagged Linux/Darwin files and must cross-compile with `CGO_ENABLED=0`.
- External core tests are opt-in; ordinary `go test ./...` stays offline.

## Work Completed

### Tasks Finished

- [x] Go module and fail-closed domain model for VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC
- [x] URI/Base64, Clash YAML, and sing-box JSON subscription parsing
- [x] HTTPS fetch limits, native/fallback secret storage, atomic state, file locking, and CAS
- [x] sing-box 1.13.14 config generation for TUN/proxy and Global/Rule/Direct routing
- [x] Secure sing-box process preparation/check/start and four-target cross-build script
- [x] Peer-authenticated Linux/macOS Unix RPC and root daemon lifecycle with rollback
- [x] Final code-quality approval for Task 5 at commit `16a14f5`
- [ ] Task 6 complete; only redaction, latency, and state consent started

## Files Modified

### Committed Partial Task 6 Files (`84e80bb`)

| File | Current state | Guidance |
|---|---|---|
| `internal/redact/redact.go` | Implemented; focused tests pass | Review regex coverage and over-redaction before keeping |
| `internal/redact/redact_test.go` | Tests URLs, share links, credentials, UUIDs, addresses | Extend with fuzz/no-panic and IPv6/domain edge cases |
| `internal/latency/checker.go` | Implemented worker-pool TCP probes and Auto Best | Review cancellation/worker cleanup and public error semantics |
| `internal/latency/checker_test.go` | Focused tests pass | Add fuzz/bounds only if useful |
| `internal/state/store.go` | Adds `Settings{TelemetryEnabled bool}` to Snapshot | Valid with strict decoder; migration policy still needs review |
| `internal/state/settings_test.go` | Tests default disabled and unknown field rejection | Keep consent strict opt-in |
The aborted agent's temporary `task_plan.md`, `findings.md`, and `progress.md` files were removed after their useful content was incorporated into this handoff.

Verification run successfully before commit `84e80bb`:

```bash
go test ./internal/latency ./internal/redact ./internal/state
git diff --check
```

Do not mark Task 6 complete until all remaining Task 6 packages and full verification pass.

## Decisions Made

| Decision | Alternatives | Rationale |
|---|---|---|
| Go + Bubble Tea + external sing-box | Embedded core; Rust | Fast cross-platform delivery and smaller privileged surface |
| GPL-3.0-only | MIT; Apache-2.0 | Keep derivatives open |
| Linux/macOS amd64/arm64 | Linux only; GUI/Windows | User selected cross-platform TUI MVP |
| TUN and loopback mixed proxy | One mode only | User selected both |
| Privileged `tuiboxd` | sudo on every connect | User selected one-time daemon installation |
| OS keychain with mode-0600 fallback | File only | Better secret storage without breaking headless Linux |
| Strict opt-in telemetry | Opt-out; none | User selected anonymous usage telemetry with explicit consent |
| Explicit typed RPC/config | Imported config pass-through | Prevent root command/config injection |
| sing-box 1.13.14 pin | Latest at runtime | Compatibility and digest verification |
| Go 1.25 minimum | Go 1.24 | `os.Root.Rename` is needed for safe atomic root-relative operations |
| QUIC protocols marked unsupported by TCP latency checker | Fake UDP success | Avoid false Auto Best results |

## Pending Work

## Immediate Next Steps

1. Enter the active worktree and inspect the partial Task 6 diff:

   ```bash
   cd /Users/rezraf/.config/superpowers/worktrees/tui-box/feature-v0.1
   git status --short --branch
   git diff
   go test ./internal/latency ./internal/redact ./internal/state
   ```

2. Review or rewrite the committed redaction/latency/settings foundation from `84e80bb`. Keep Task 6 unchecked until the remaining packages and two-stage review are complete.

3. Finish Task 6 test-first:
   - `internal/telemetry`: strict allowlisted event struct, disabled by default, no-op without HTTPS build-time endpoint;
   - `internal/app`: transactional Add/List/Update/Remove subscriptions, refresh last-known-good behavior, credential-free server projections, manual/auto Connect, Disconnect, Status, Doctor;
   - `internal/cli`: Cobra command tree and English output;
   - `cmd/tuibox/main.go`: unprivileged entry point and build info;
   - updater remains an injected interface until Task 8.

4. Implement Task 7 Bubble Tea TUI with server selection, subscription input, refresh, latency, mode/route cycling, connect/disconnect, and testable update logic.

5. Implement Task 8 installer/updater/GitHub automation. The user explicitly requested GitHub CI/CD and releases:
   - `install.sh`, `uninstall.sh`;
   - systemd service and launchd plist using `tuiboxd --core --runtime-dir --socket --socket-gid --allow-uid`;
   - install separate pinned sing-box 1.13.14 and verify official GitHub asset digest;
   - `internal/update` GitHub Release client with exact platform asset selection and SHA-256 verification;
   - `.github/workflows/ci.yml`: format, tests, race, vet, build, shell syntax, four-target cross-build;
   - required pinned-core job with `TUIBOX_CORE_INTEGRATION=1`;
   - `.github/workflows/release.yml`: tag-driven four archives, checksums, generated changelog/release notes, GitHub build provenance/attestation;
   - Dependabot for Go and GitHub Actions;
   - do not auto-update in the background.

6. Implement Task 9 English OSS documentation and governance: README, GPL-3.0-only LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, architecture/security/telemetry docs, issue forms, PR template.

7. Complete Task 10 adversarial security review, full verification, merge `feature/v0.1` to `main`, and only then consider pushing/releasing.

8. Final cleanup requested by the user: remove only TuiBox development/test caches and build artifacts; do not delete unrelated machine caches.

### Blockers/Open Questions

- No functional blocker is known.
- No telemetry collection endpoint was supplied. Keep telemetry as a no-op when the build-time endpoint is empty. Never invent or hardcode an endpoint.
- Release signing choice is not fully fixed. GitHub build provenance is required; adding keyless Sigstore/cosign is acceptable if installer verification remains reliable.
- The current remote appears to have no usable `origin/main` history (`origin/main [gone]`). Do not push until local branch integration and release files are reviewed.
- The root credential-drop tests compile everywhere but may skip on non-root local runs. A Linux CI job can run the relevant test as root.

### Deferred Items

- Windows, mobile, and GUI support
- Custom routing-rule editor
- Load balancing and user-defined groups
- Background automatic updates
- Multiple concurrent daemon sessions/users
- Encrypted endpoint cache beyond OS permissions

## Context for Resuming Agent

## Important Context

- Work in `/Users/rezraf/.config/superpowers/worktrees/tui-box/feature-v0.1`, not `/Users/rezraf/tui-box`. The primary checkout only contains the initial design commit.
- The feature branch is 26+ commits ahead of `main`. Do not reset or recreate completed Tasks 1–5.
- Task 6 has committed partial code in `84e80bb`. Preserve it or deliberately rewrite it; it has tests but has not yet passed separate spec/quality review.
- Tasks 1–5 have already passed repeated spec and quality reviews. Changes to their security boundaries require regression tests and another review.
- Never pass provider Clash/sing-box configuration directly to the root daemon. Always normalize into `domain.Endpoint` and regenerate config.
- `rpc.ConnectPayload` intentionally excludes caller identity, paths, executable, args, and environment. UID/GID come only from kernel peer credentials.
- `tuiboxd` authorization has no implicit root bypass. Every allowed UID, including `0` if desired, must be explicit.
- sing-box config is parent-verified and piped with the native `-c stdin` token. Do not revert to `/dev/fd` or user paths.
- Integration tests must remain offline by default. Run the official core matrix explicitly with `TUIBOX_CORE_INTEGRATION=1`.
- All repository prose, CLI output, logs, issues, and docs must be English.

## Assumptions Made

- GitHub repository remains `github.com/rezraf/tui-box`.
- Product name is TuiBox; command is `tuibox`.
- Local proxy binds only to `127.0.0.1:2080`.
- One daemon-managed session is enough for v0.1.
- Subscription URL is a secret; cached endpoints also contain credentials and stay mode 0600.
- Telemetry is strict opt-in and contains no endpoint address/name, IP, URL, token, log, destination, or stable installation ID.

## Potential Gotchas

- Go minimum is 1.25, not 1.24.
- `state.Snapshot` uses a schema version and revision. Adding Settings must preserve strict unknown-field rejection and consider existing state migration before release.
- `state.Store` and `secrets.Store` own `os.Root` descriptors and must be closed.
- `rpc.Client` operations are one-request-per-connection and context cancellation is propagated through socket closure.
- Daemon session replacement waits for confirmed process exit; Kill alone is not treated as exit.
- `scripts/cross-build.sh` currently covers binaries present at the time; update it when `cmd/tuibox` is added.
- The partial redactor is regex-based and unreviewed. Verify it neither leaks edge cases nor destroys ordinary CLI messages.
- Do not treat Hysteria2/TUIC UDP dialing as real latency success.
- Avoid tests that require live GitHub in ordinary `go test ./...`; use a dedicated integration job.
- Never log raw `domain.Endpoint`, subscription documents, URLs, RPC request bodies, or sing-box output.

## Environment State

### Tools/Services

- Go: `go1.26.2 darwin/arm64`
- Module minimum: Go 1.25
- Git worktree branch: `feature/v0.1`
- No golangci-lint, shellcheck, or goreleaser was installed during the session.
- Official sing-box release checked: `v1.13.14`
- Darwin arm64 asset digest previously verified: `73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab`

### Active Processes

- None. No daemon, server, watcher, or sing-box process was intentionally left running.

### Environment Variable Names

- `TUIBOX_CORE_INTEGRATION` — enables official pinned-core integration tests
- `TUIBOX_SING_BOX` — optional explicit core binary for integration tests
- Future client override proposed: `TUIBOX_SOCKET`
- Future build-time telemetry endpoint should be an ldflag, not a runtime secret

## Verification Commands

Run before accepting partial work:

```bash
cd /Users/rezraf/.config/superpowers/worktrees/tui-box/feature-v0.1
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/tuiboxd
./scripts/cross-build.sh
git diff --check
```

Run the external compatibility matrix explicitly:

```bash
TUIBOX_CORE_INTEGRATION=1 go test ./internal/core -count=1
```

After `cmd/tuibox` exists, require:

```bash
go build ./cmd/tuibox ./cmd/tuiboxd
go run ./cmd/tuibox --help
```

## Related Resources

- `.agent/SPECS/tuibox-v0.1.md`
- `.agent/DECISIONS/tuibox-v0.1.md`
- `.agent/TODOS/tuibox-v0.1.md`
- `docs/plans/2026-07-13-tuibox-v0.1.md`
- `docs/plans/2026-07-13-tuibox-v0.1-design.md`
- `https://github.com/rezraf/tui-box`
- `https://github.com/SagerNet/sing-box/releases/tag/v1.13.14`

---

**Security reminder:** Validate this handoff before transfer. It intentionally contains no subscription URL, credentials, API token, or private endpoint.
