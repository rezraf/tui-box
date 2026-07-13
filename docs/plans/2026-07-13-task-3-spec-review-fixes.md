# Task 3 Spec-Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Task 3 storage and fetching boundaries safe across processes, bounded on disk and network, operationally probed, and resistant to symlinked ancestors.

**Architecture:** Keep package APIs narrow. Add advisory file locks around complete read-modify-write transactions, validate state collection and serialized-size boundaries before atomic writes, normalize HTTP timeouts at construction, probe native stores with direct bounded commands, and centralize secure path ancestry checks. Preserve the macOS stdin password protocol with `-w` last.

**Tech Stack:** Go, `golang.org/x/sys/unix`, `os/exec`, `encoding/json`, standard Go tests.

---

### Task 1: Preserve macOS stdin password handling and clamp fetch timeouts

**Files:**
- Modify: `internal/secrets/command_store_test.go`
- Modify: `internal/secrets/command_store.go`
- Modify: `internal/subscription/fetcher_test.go`
- Modify: `internal/subscription/fetcher.go`

1. Add a focused test proving macOS `-w` is the final argument and the secret exists only on stdin.
2. Add table tests for zero, negative, exactly 15 seconds, over 15 seconds, and shorter positive timeouts.
3. Run each focused test and record the expected failure before implementation.
4. Add the concise source comment and minimal timeout normalization.
5. Re-run focused package tests.

### Task 2: Bound and lock state updates

**Files:**
- Modify: `internal/state/store_test.go`
- Modify: `internal/state/store.go`
- Create if needed: `internal/state/lock_unix.go`

1. Add boundary tests for maximum subscription count, endpoint count, and encoded state size.
2. Add a concurrent lost-update test using two independently constructed stores for one path.
3. Verify failures identify missing count/size validation and process-wide locking.
4. Add explicit limits, pre-write serialized-size rejection, and a mode-0600 advisory lock covering load/modify/save.
5. Re-run state tests, including repeated concurrency execution.

### Task 3: Lock fallback secret updates

**Files:**
- Modify: `internal/secrets/file_store_test.go`
- Modify: `internal/secrets/file_store.go`
- Create if needed: `internal/secrets/lock_unix.go`

1. Add independent-store concurrent update tests and lock permission assertions.
2. Verify the lost-update regression fails reliably.
3. Add mode-0600 advisory locking around complete fallback secret transactions.
4. Re-run secret tests and race tests.

### Task 4: Probe native backend operation

**Files:**
- Modify: `internal/secrets/store_test.go`
- Modify: `internal/secrets/store.go`
- Modify if needed: `internal/secrets/command_store.go`

1. Add tests for successful macOS/Linux direct probes, failed probes falling back with warning, bounded contexts, and no shell use.
2. Verify selection tests fail because lookup alone currently selects native stores.
3. Implement short direct probes: harmless macOS keychain-list and Linux Secret Service search.
4. Re-run secret package tests.

### Task 5: Reject malicious symlinked ancestors

**Files:**
- Modify: `internal/state/store_test.go`
- Modify: `internal/state/store.go`
- Modify: `internal/secrets/file_store_test.go`
- Modify: `internal/secrets/file_store.go`
- Create shared internal path package only if duplication warrants it.

1. Add nested-ancestor symlink tests and a macOS-style `/var` to `/private/var` compatibility test where feasible.
2. Verify current checks accept malicious ancestors.
3. Canonicalize a trusted existing prefix and reject symlinks below it without rejecting OS-managed prefix aliases.
4. Re-run state and secret tests.

### Task 6: Verify, update TODO, and commit

**Files:**
- Modify: `.agent/TODOS/tuibox-v0.1.md` only if needed after all checks

1. Run `gofmt` on changed Go files.
2. Run `go test -count=1 ./internal/subscription ./internal/secrets ./internal/state`.
3. Run `go test -race ./internal/secrets ./internal/state`.
4. Run `go vet ./internal/subscription ./internal/secrets ./internal/state`.
5. Run `git diff --check`.
6. Confirm Task 3 is checked only after successful verification.
7. Review `git status`, unstaged diff, staged diff, and scan for secrets/debug artifacts.
8. Commit once with a Conventional Commit message and report the SHA.
