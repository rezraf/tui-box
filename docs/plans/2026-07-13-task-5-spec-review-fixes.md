# Task 5 Spec Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close every Task 5 RPC, authorization, concurrency, and lifecycle review finding without weakening redaction or replacement rollback.

**Architecture:** Keep the newline-delimited RPC shape, but scan every JSON object before decoding so keys are canonical and duplicates fail closed. Serialize daemon service state with a one-token channel gate so request contexts can cancel queueing. Authenticate accepted Unix peers under a short deadline before admission, and stop sessions with one caller-bounded grace window followed by at most one kill attempt.

**Tech Stack:** Go standard library, `x/sys/unix`, package-focused tests, race detector, `go vet`, and cross-compilation.

---

### Task 1: Harden strict RPC decoding

**Files:**
- Modify: `internal/rpc/protocol_test.go`
- Modify: `internal/rpc/protocol.go`

**Steps:**
1. Add regressions for case-insensitive duplicates at top-level and nested object depths, mixed-case schema keys, missing/null/forbidden `connect`, and strict response keys.
2. Run `go test ./internal/rpc -run 'TestDecode|TestValidateRequest'` and confirm the new cases fail for the reviewed reasons.
3. Canonicalize object keys during recursive token scanning and track top-level `connect` presence independently from its decoded pointer value.
4. Run the focused protocol tests and all RPC tests.

### Task 2: Make service serialization context-aware

**Files:**
- Modify: `internal/daemon/service_test.go`
- Modify: `internal/daemon/service.go`
- Modify: `internal/rpc/server.go`
- Modify: `internal/rpc/server_test.go`

**Steps:**
1. Add regressions proving expired queued Connect, Disconnect, Status, and Health calls return their context error and never mutate state.
2. Run the focused service tests and confirm failures against mutex queueing and the old Status interface.
3. Replace the state mutex with a one-token channel gate, check context while waiting and immediately after acquisition, and make Status return `(SessionStatus, error)` through the dispatcher.
4. Run focused service and dispatcher tests under the race detector.

### Task 3: Bound session stopping once

**Files:**
- Modify: `internal/daemon/service_test.go`
- Modify: `internal/daemon/service.go`

**Steps:**
1. Add regressions for cancellation during graceful stop and for a process whose Wait never completes after Kill.
2. Confirm the old implementation ignores caller cancellation and waits a second full timeout.
3. Have the monitor close one session-done channel, wait once for TERM using the earlier of caller cancellation and `stopTimeout`, issue KILL once, and return immediately.
4. Preserve pointer-and-generation checks in monitor cleanup and rerun replacement rollback/redaction lifecycle tests.

### Task 4: Enforce exact UID authorization before admission

**Files:**
- Modify: `internal/rpc/server_test.go`
- Modify: `internal/rpc/client_test.go`
- Modify: `internal/rpc/server.go`
- Modify: `internal/rpc/client.go`
- Modify: `cmd/tuiboxd/main_test.go`

**Steps:**
1. Add regressions for root denied unless explicitly listed, empty allowlist rejection, explicit UID 0 CLI acceptance, pre-auth access-denied handling, and unauthorized peers not consuming a saturated slot.
2. Run focused RPC and daemon CLI tests and confirm failures.
3. Remove the root bypass, reject empty allowlists, register accepted connections for shutdown, authenticate under a short deadline before semaphore admission, reset deadlines for admitted peers, and recognize the stable pre-auth denial response in the client.
4. Run focused tests and race tests.

### Task 5: Final verification and commit

**Files:**
- Review all modified files.

**Steps:**
1. Run `gofmt` and focused package tests.
2. Run `go test -race ./...`, `go test ./...`, `go vet ./...`, and native builds.
3. Cross-build supported Linux/macOS amd64/arm64 targets with `CGO_ENABLED=0`.
4. Run `git diff --check`, inspect staged diff for redaction and rollback regressions, and commit once with a Conventional Commit message.
5. Report the exact verification results and commit SHA.
