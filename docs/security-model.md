# Security Model

## Security goals

TuiBox aims to:

- keep subscription URLs and endpoint credentials out of normal output, logs, state references, and telemetry;
- prevent untrusted subscription content from becoming commands or arbitrary sing-box configuration;
- limit root functionality to authenticated local connection control;
- reject unsafe filesystem ownership, permissions, symlinks, archives, and executable paths;
- bound network responses, parser entries, RPC messages, concurrency, timeouts, generated configs, and captured core output;
- fail closed with stable public errors instead of exposing internal/provider/core details.

## Assets

- Subscription URLs and embedded endpoint credentials.
- Normalized endpoint cache and telemetry consent.
- Root privileges held by `tuiboxd`.
- The installed `tuibox`, `tuiboxd`, update helper, and sing-box binaries.
- Generated sing-box runtime configuration.
- Integrity of the local RPC session and active routes.

## Trust boundaries

### Subscription provider boundary

Subscription URLs and documents are untrusted network input. Fetches require HTTPS, are time/size bounded, and reject downgrade redirects. TuiBox parses supported fields into a closed domain model; it does not execute provider-supplied Clash/sing-box configuration.

HTTPS authenticates the transport endpoint according to the host trust store. It does not make the provider or document trustworthy. Imported fields can request `insecure`/`skip-cert-verify`; valid requests are preserved, so users must trust their provider.

### User client boundary

`tuibox` runs with the invoking user's privileges. It owns user state, credential access, subscription fetching, parsing, latency probes, UI, and update initiation. It does not create TUN devices or directly run the privileged daemon.

### Root daemon boundary

`tuiboxd` requires effective root and accepts only a fixed RPC schema over a local Unix socket. The installer authorizes one UID and assigns the socket to that user's primary group. Socket mode alone is not authorization: the daemon reads kernel peer credentials and checks the UID allowlist.

Requests cannot provide UID/GID, executable paths, config paths, arbitrary commands, arguments, or environment variables. The RPC schema supports only connect, disconnect, status, and health.

### Core boundary

sing-box is trusted code pinned by the installer to version `1.13.14`. TuiBox validates its ownership/path/permissions and, on Linux, rejects file capabilities. Generated configuration is checked by sing-box before start.

TuiBox does not sandbox sing-box beyond service-manager controls, process identity selection, an empty environment, bounded output capture, and generated configuration. A sing-box vulnerability is primarily an upstream concern, though a TuiBox path that makes it exploitable is in scope.

### Update boundary

The installer and updater trust HTTPS GitHub release metadata/assets plus SHA-256 checksums fetched from the same release trust domain. Archive paths/types and installed layouts are validated.

Checksums are not independent signatures. The release workflow keeps assets in a draft until provenance exists for every archive and for `checksums.txt`, then publishes in its final step. The installer/updater do not verify those attestations or any artifact signature.

## Implemented controls

### Filesystem

- User state/config directories: exact mode `0700`.
- User state/fallback secret files: regular exact mode `0600`.
- Daemon runtime directory: root-owned exact mode `0700`.
- Generated configs: random names, regular mode `0600`, atomic rename, sync, ownership and digest revalidation.
- Socket: validated ancestors, no symlink substitution, mode `0660`, expected owner/group.
- Core/update binaries: regular, non-symlink, trusted parents, no group/other write, root ownership for privileged replacement.

### Input and resource bounds

- Subscription response/document: 10 MiB.
- Subscription entries: 10,000; each at most 64 KiB.
- RPC frame: 256 KiB; JSON nesting: 32.
- RPC default concurrency: 32.
- Updater metadata/checksum/archive/binary/extracted sizes are bounded.
- Generated config: 128 KiB.
- Captured core output: 64 KiB.
- Subscription, RPC, update, telemetry, and shutdown operations have deadlines or bounded waits.

### Secrets and output

- Native credential commands are executed directly, never through a shell.
- macOS secret input is supplied through standard input; Linux `secret-tool` also receives the secret on standard input.
- State stores secret references, not subscription URLs.
- CLI/TUI expose projected fields and stable errors.
- sing-box logs are disabled in generated configs.
- Redaction covers URLs/userinfo/query values, bearer tokens, credentials, endpoint hosts/addresses, and UUID-like values where practical.

Redaction is defense in depth, not a license to log sensitive structures. Raw documents, endpoint structs, RPC payloads, and core output must not be logged.

### Privilege minimization

- Proxy mode drops the core process to the authenticated caller UID/GID and listens on loopback only.
- TUN mode remains privileged because route/interface setup requires it.
- Linux systemd uses `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectSystem=strict`, and restricted writable paths.
- The daemon accepts a single configured UID allowlist from the installed service definition.

## Threats and residual risk

### Malicious subscription

Mitigated by strict formats, closed protocol/transport models, validation, size limits, warning redaction, and no direct execution. Residual risk remains in accepted endpoint values, upstream core parsing/behavior, and provider-requested insecure TLS.

### Local unprivileged attacker

Mitigated by private directories, socket ownership/mode, peer credentials, UID allowlist, strict RPC, and root-owned executable paths. A user already able to act as the authorized UID can request connections and updates through the same interfaces as that user.

### Filesystem race or symlink attack

Mitigated with `os.Root`, `Lstat`, `O_NOFOLLOW` where used, ownership/mode checks, same-file checks, atomic replacement, and post-operation validation. The model assumes a non-compromised kernel and filesystem semantics compatible with Linux/macOS.

### Network or release compromise

HTTPS and SHA-256 catch transport corruption and mismatch against fetched checksums. They do not defend against compromise of the release account/workflow or a trust-domain attacker able to replace both archive and checksum.

### Root or host compromise

Out of scope. A root attacker can read user/process data, replace services/binaries, alter routes, and bypass local controls.

## Non-goals

TuiBox does not promise:

- anonymity, unlinkability, censorship resistance, or protection from a malicious provider/relay;
- protection after root, kernel, authorized user, Keychain, Secret Service, service manager, or sing-box compromise;
- remote or multi-user administration;
- safe handling of arbitrary provider-specific fields outside the normalized model;
- independent release signatures;
- automatic daemon restart after update;
- deletion of native credential entries during uninstall;
- telemetry transmission in v0.1.

## Security-sensitive maintenance rules

Changes to RPC, process identity, paths, archives, updates, subscription parsing, redaction, telemetry, or secret storage require adversarial tests. Ordinary tests must not contact external services. Public bug reports and fixtures must use synthetic credentials only.

Report vulnerabilities through [SECURITY.md](../SECURITY.md).
