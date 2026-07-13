# Task 4 Secure Runner Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace caller-controlled config paths with runner-owned prepared handles, descriptor-only core execution, strict executable trust checks, bounded Rule routing inputs, pinned integration downloads, and four-target build verification.

**Architecture:** `NewRunner` fixes and holds an `os.Root` for an existing private runtime directory. `Prepare` generates validated JSON, writes a unique mode-0600 temporary file, syncs it, and atomically renames it inside that root; the returned `*PreparedConfig` exposes only `Close`. `Check` and `Start` verify the tracked digest from an open internal file and pass that same file as descriptor 3 while sing-box receives only the fixed path `/dev/fd/3`. A successful check records the exact digest; start requires and reverifies it. The runner and every handle own idempotent cleanup lifecycles.

**Tech Stack:** Go 1.25+, `os.Root`, `os/exec.ExtraFiles`, `crypto/sha256`, `net/netip`, Unix credentials, Go archive/tar and gzip, shell cross-build verification.

**Design decision:** A runner-owned concrete opaque handle is preferable to path tokens or serialized IDs because it prevents arbitrary path injection and keeps ownership/lifecycle checks in-process. Passing config bytes on stdin was rejected because sing-box's fixed CLI consumes a config path and descriptor inheritance also works after UID/GID drop. Reopening an internal pathname was rejected because it recreates path races and prevents a dropped proxy process from reading a root-owned mode-0600 config.

---

### Task 1: Add RED tests for bounded Rule routing

**Files:**
- Modify: `internal/core/config_test.go`
- Create: `internal/core/testdata/golden/proxy-global.json`
- Create: `internal/core/testdata/golden/proxy-rule.json`
- Create: `internal/core/testdata/golden/tun-rule.json`
- Create: `internal/core/testdata/golden/tun-direct.json`

**Steps:**
1. Add table tests that require all six Proxy/TUN × Global/Rule/Direct structures.
2. Add Rule-only direct domain suffix and `netip.Prefix` cases, distinct emitted rules, and a Rule golden.
3. Add rejection tests for fields outside Rule mode, invalid domains, invalid/noncanonical prefixes, duplicates, and list bounds.
4. Run focused tests and confirm they fail because the fields and validation do not exist.
5. Add the minimal config types, validation, normalization, and route mapping; update all six goldens.
6. Run focused tests until green.

### Task 2: Add RED tests for the prepared-config API

**Files:**
- Replace obsolete path tests in: `internal/core/process_test.go`
- Modify: `internal/core/testdata/corehelper/main.go`

**Steps:**
1. Test the constructor-fixed mode-0700 euid-owned runtime root and executable owner/parent trust policy.
2. Test `Prepare` creates unique atomic mode-0600 files and exposes no caller path.
3. Test fixed command arguments are exactly `check|run -c /dev/fd/3`, with one `ExtraFiles` entry and an empty environment.
4. Test start-before-check, cross-runner handles, tampering after prepare/check, closed handles, runner close, and cleanup.
5. Add a root-only real proxy execution test that drops to an unprivileged UID/GID and proves the helper reads the inherited root-owned config.
6. Run the process tests and confirm compile/failure output is caused by the missing API.
7. Implement the minimal prepared handle, root lifecycle, atomic write, digest gate, inherited-FD execution, and trust validation.
8. Run focused process tests until green.

### Task 3: Add RED integration behavior and secure downloader

**Files:**
- Modify: `internal/core/config_integration_test.go`

**Steps:**
1. Make `-short` the only default skip when `TUIBOX_SING_BOX` is absent.
2. Add a four-target artifact table with pinned 1.13.14 URLs and hardcoded official SHA-256 values.
3. Add HTTPS-only bounded download, digest verification, safe tar extraction, and cache reuse.
4. Update the complete 10-endpoint × 2-mode × 3-route matrix to use `Prepare` then `Check`, retaining 60 checks.
5. Run the integration test and confirm it fails before downloader/API implementation, then make it green.

### Task 4: Add four-target compile verification

**Files:**
- Create: `scripts/cross-build.sh`

**Steps:**
1. Add a strict POSIX shell loop for darwin/linux and amd64/arm64.
2. Compile all current packages with `CGO_ENABLED=0` for each target.
3. Run the script and retain exact output for the final report.

### Task 5: Final verification and commit

**Files:**
- Update: `.agent/TODOS/tuibox-v0.1.md` only after every gate passes.

**Steps:**
1. Run `gofmt` on all changed Go files and `git diff --check`.
2. Run `go test ./...`, `go test -race ./...`, and `go vet ./...`.
3. Run the pinned integration test explicitly and confirm at least 60 core checks.
4. Run `./scripts/cross-build.sh`.
5. Review the full diff for obsolete path APIs/tests, arbitrary args/env/paths, secrets, unsafe archive extraction, and unintended changes.
6. Mark Task 4 checked only while all evidence remains green.
7. Stage only Task 4 files, inspect `git diff --cached`, and commit with a Conventional Commit message.
8. Report the commit SHA and exact verification results.
