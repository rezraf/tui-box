# Architecture

## Overview

TuiBox separates user-facing state and network ingestion from privileged connection control.

1. `tuibox` runs as the invoking user.
2. The client stores normalized subscriptions/endpoints and consent in user state.
3. Subscription URLs are stored in an OS credential backend or a restricted fallback file.
4. The client sends only validated connection operations over a local Unix socket.
5. `tuiboxd` runs as root, authenticates the socket peer, revalidates the request, generates a bounded sing-box config, runs `sing-box check`, and manages one core process.

The subscription provider never supplies an executable path, command, environment, service definition, or raw sing-box configuration to the daemon.

## Components

### `cmd/tuibox`

Composition root for the CLI and TUI. It resolves user data/config directories, validates `TUIBOX_SOCKET`, opens stores lazily for operational commands, creates bounded clients, and wires the updater only for non-`dev` builds.

Help, version, completion, and usage failures do not open state, secrets, daemon RPC, network clients, or update flows.

### `internal/cli`

Cobra command surface. Operational output uses safe projections and stable errors. Most data commands emit JSON. Usage failures return exit code `2`; operational failures return `1`.

### `internal/tui`

Bubble Tea model for server selection, subscription addition, refresh, latency checks, connect/disconnect, and status. It uses the same application service as the CLI and only displays projected labels, protocols, latency, status, and stable error text.

### `internal/app`

Application orchestration. It owns subscription lifecycle, cache-preserving refresh, state/secret rollback behavior, latency result projection, Auto Best selection, routing requests, diagnostics, telemetry consent, and updater delegation.

### `internal/subscription`

HTTPS-only bounded fetcher and parsers for URI lists, Base64, Clash YAML, and sing-box JSON. Parsers normalize supported endpoint fields, derive stable scoped IDs, deduplicate entries, and return redacted warnings for skipped entries.

### `internal/state` and `internal/secrets`

- State is schema-versioned JSON with atomic replacement, locking, strict decoding, mode-`0600` files, and mode-`0700` directories.
- State contains subscription metadata and the normalized endpoint cache, including endpoint credentials.
- Subscription source URLs use macOS Keychain or Linux Secret Service when available.
- The source-URL fallback store is a separate mode-`0600` JSON file in the private config directory.

State stores source-URL secret references, not the subscription URLs themselves.

### `internal/rpc`

Versioned newline-delimited JSON over a Unix socket. The server bounds frame size, concurrency, authentication time, read/write time, and operation time. It rejects unknown fields, duplicate/case-variant JSON keys, excessive nesting, malformed identities, and unauthorized peer UIDs.

The caller UID/GID comes from kernel peer credentials. Identity fields are not accepted in the request payload.

### `cmd/tuiboxd` and `internal/daemon`

The daemon requires effective UID `0`. It permits only `connect`, `disconnect`, `status`, and `health`. It serializes session transitions, validates replacement configs before stopping the current session, attempts rollback if replacement fails, and manages a single active core process.

### `internal/core`

Maps the normalized endpoint model to typed sing-box JSON. The runner:

- accepts only an absolute trusted sing-box executable;
- rejects symlinks, writable executable/parent paths, setuid/setgid bits, and Linux file capabilities;
- uses a root-owned mode-`0700` runtime directory;
- writes generated mode-`0600` configs atomically;
- rechecks file identity and digest before execution;
- runs sing-box with an empty environment and config on standard input;
- uses a process group for bounded termination.

In Proxy mode, the core process drops to the authenticated caller UID/GID. In TUN mode, it remains under the root daemon because network-interface and routing changes require privilege.

### `internal/update`

Stable-release checker and installed-layout updater. It accepts Linux/macOS amd64/arm64 assets, requires HTTPS, applies bounded downloads and redirects, verifies SHA-256, rejects unsafe archives, and uses staged replacement with backups and rollback.

The unprivileged client verifies that the update helper and its parent chain are root-owned and non-writable before invoking it via `/usr/bin/sudo`. After elevation, the helper independently validates effective root, the installed layout, ownership, permissions, release metadata, checksum, and archive before replacement.

### `internal/telemetry`

Closed telemetry event schema and hardened HTTPS sender. v0.1 persists consent but does not instantiate this sender or configure an endpoint, so no telemetry is transmitted.

## Data flow

### Add or refresh a subscription

1. The client validates the subscription name and source URL input, or resolves the stored URL for a refresh.
2. The fetcher downloads at most 10 MiB with a 15-second timeout and enforces HTTPS.
3. A parser normalizes valid endpoints and redacts warnings.
4. For a new subscription, the URL is written to the secret backend only after a valid endpoint set is available.
5. State commits the subscription and endpoint cache atomically.
6. A failed refresh keeps the last valid endpoint cache.

### Connect

1. The app selects a manual endpoint, Auto Best result, or no endpoint for Direct routing.
2. The RPC client sends a bounded typed request.
3. The daemon authenticates the Unix peer and derives UID/GID.
4. The core layer generates a config and runs `sing-box check`.
5. Only a checked, unchanged config may start.
6. Proxy mode drops to the caller identity; TUN mode remains privileged.
7. The daemon tracks status and owns process termination/rollback.

### Update

1. The client checks stable GitHub Releases.
2. On apply, it invokes the installed helper through `/usr/bin/sudo`.
3. The helper repeats metadata and asset selection as root.
4. It verifies the archive against `checksums.txt`, extracts only `tuibox` and `tuiboxd`, and replaces the installed client, daemon, and helper.
5. The running daemon is not restarted automatically.

## Fixed v0.1 behavior

- Mixed proxy inbound: `127.0.0.1:2080`.
- TUN interface/address: `tuibox0`, `172.19.0.1/30`.
- DNS: direct UDP `1.1.1.1:53`, `prefer_ipv4`.
- One active daemon session.
- Private networks and `.lan`, `.local`, `.localhost` remain direct.
- Rule-mode direct lists exist internally but have no user-facing editor.

See [security-model.md](security-model.md) for threats and [telemetry.md](telemetry.md) for the dormant telemetry schema.
