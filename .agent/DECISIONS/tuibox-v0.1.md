# TuiBox v0.1 Decisions

## Status

Accepted for implementation on 2026-07-13.

## Product decisions

- Publish all repository content, CLI copy, logs, and documentation in English.
- Target Linux and macOS on amd64 and arm64.
- Use the product name **TuiBox** and the command name `tuibox`.
- License TuiBox under GPL-3.0-only.
- Support TUN and local mixed HTTP/SOCKS proxy modes.
- Support VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC endpoints.
- Import URI lists, Base64 subscriptions, Clash YAML, and sing-box JSON.
- Provide Global, Rule, and Direct routing modes.
- Provide manual selection and Auto Best latency selection.
- Store subscription URLs in the OS credential store when available. Fall back to a mode-0600 file and show a warning.
- Keep usage telemetry disabled until the user explicitly opts in. Never collect subscription URLs, endpoint addresses, credentials, IP addresses, server names, traffic destinations, or logs.
- Update through `tuibox update`, with release digest verification.

## Architecture

Use two Go binaries and a separately distributed sing-box runtime:

1. `tuibox` runs without privileges and owns the TUI, subscription import, local state, latency measurements, and update UX.
2. `tuiboxd` is a small privileged daemon installed through systemd or launchd. It owns TUN lifecycle and starts validated sing-box sessions.
3. `sing-box` remains a separate executable with its own version and license.

The daemon listens on a Unix socket owned by root and the installing user's primary group. It also verifies peer credentials against an installer-provided UID allowlist. It accepts a fixed JSON request schema and never accepts shell commands, arbitrary process arguments, environment variables, or config paths.

The daemon reconstructs sing-box configuration from a validated endpoint model. It does not execute imported provider configuration directly.

## Rejected approaches

### Embed sing-box as a Go library

Rejected because it couples releases to internal core APIs, expands the privileged binary, and complicates independent security updates.

### Implement proxy protocols in TuiBox

Rejected because custom cryptographic protocol code would increase risk and maintenance cost without improving the user experience.

### Rust client

Rejected for v0.1 because Go provides faster delivery, straightforward cross-compilation, and a mature TUI ecosystem. Rust remains viable if measured resource use later justifies a rewrite.

### Passwordless arbitrary root helper

Rejected. The daemon API remains narrow, typed, peer-authenticated, and allowlisted.

## Autonomous implementation assumptions

- The repository is new and has no initial commit. Worktree isolation is not possible until a baseline commit exists, so v0.1 is implemented in the clean primary worktree.
- The public repository is `github.com/rezraf/tui-box`.
- TuiBox release artifacts use GitHub Releases. CI publishes checksums and provenance attestations.
- The initial compatible core is sing-box 1.13.14. Maintainers update the pin after compatibility tests pass.
- v0.1 supports one active daemon-managed session at a time.
- Proxy mode binds only to loopback by default.
- Custom routing-rule editing, load balancing, Windows, mobile platforms, and a GUI are deferred.
