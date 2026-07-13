# TuiBox

TuiBox is a terminal client for subscription-based proxy services on Linux and macOS. It imports common subscription formats, normalizes supported endpoints, measures TCP reachability, and manages a pinned [sing-box](https://github.com/SagerNet/sing-box) runtime through a local privileged daemon.

TuiBox v0.1 is pre-release software. Review the [limitations](#limitations) and [security model](docs/security-model.md) before using it for sensitive traffic.

## Features

- Interactive Bubble Tea server selector and scriptable CLI.
- VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC endpoints.
- URI lists, whole-document Base64, Clash YAML `proxies`, and sing-box JSON `outbounds`.
- TUN and local mixed HTTP/SOCKS proxy modes.
- Global, rule, and direct routing modes.
- macOS Keychain or Linux Secret Service storage when available, with a restricted local-file fallback.
- Root daemon isolated behind a peer-authenticated Unix socket.
- Release archive and pinned sing-box SHA-256 verification.
- Telemetry consent controls. No telemetry endpoint is configured or used in v0.1.

## Supported systems

| Operating system | Architectures | Service manager |
| --- | --- | --- |
| Linux | amd64, arm64 | systemd |
| macOS | amd64, arm64 | launchd |

Windows, mobile platforms, and other Unix systems are not supported.

## Install

Requirements:

- Linux with systemd or macOS with launchd.
- `curl`, `tar`, and either `sha256sum` or `shasum`.
- `jq` when `TUIBOX_VERSION` is not set and the installer must resolve a release.
- `/usr/bin/sudo` when not already running as root.
- A compatible GitHub Release for the selected version.

From a checked-out source tree:

```sh
sh install.sh
```

By default, the installer queries GitHub release metadata and selects the highest canonical `v<major>.<minor>.<patch>` release that is neither a draft nor a prerelease. It does not use GitHub's moving `releases/latest` alias. To request a specific stable tag deterministically:

```sh
TUIBOX_VERSION=v0.1.0 sh install.sh
```

An explicit `TUIBOX_VERSION` skips metadata resolution and uses only tag-specific download URLs.

The installer:

1. detects Linux/macOS and amd64/arm64;
2. resolves the highest published stable release unless an explicit tag was supplied;
3. downloads the matching `tuibox_<os>_<arch>.tar.gz` and `checksums.txt` over HTTPS from that tag;
4. verifies the release archive SHA-256 digest;
5. downloads sing-box `1.13.14` and verifies a platform-specific pinned SHA-256 digest;
6. installs `tuibox`, `tuiboxd`, the update helper, and sing-box under `/usr/local/libexec/tuibox`;
7. links `/usr/local/bin/tuibox`;
8. installs and starts the system service for the user who invoked the installer.

The release workflow keeps release assets in a draft, attests every checksummed archive and `checksums.txt`, then publishes and marks the release latest in its final step. The installer verifies checksums, but it does **not** verify an artifact signature or provenance attestation.

### Build for development

Go `1.25` is declared in `go.mod`.

```sh
go build ./cmd/tuibox ./cmd/tuiboxd
```

A development build reports version `dev`; its updater is intentionally unavailable. Building the binaries alone does not install sing-box or the privileged service.

## First connection

Subscriptions must use HTTPS.

```sh
tuibox subscription add "My provider" "https://provider.example/subscription"
tuibox subscription list
tuibox server list
tuibox server latency --all
tuibox connect auto --mode proxy --route global
tuibox status
```

`subscription add`, `subscription list`, and `server list` return JSON. Use the returned subscription and endpoint IDs for later commands.

Proxy mode starts a local mixed HTTP/SOCKS inbound on `127.0.0.1:2080`. Point applications at that address; TuiBox does not set shell proxy variables for you. TUN mode asks sing-box to create `tuibox0` and install automatic routes.

Disconnect with:

```sh
tuibox disconnect
```

Direct routing still requires the CLI target position, but does not use an endpoint:

```sh
tuibox connect auto --mode tun --route direct
```

## Interactive TUI

Run `tuibox` in an interactive terminal. The initial selection is Auto Best, TUN mode, and Global routing.

| Key | Action |
| --- | --- |
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Enter` | Select the highlighted server manually |
| `a` | Select Auto Best |
| `m` | Toggle TUN and Proxy modes |
| `r` | Cycle Global, Rule, and Direct routing |
| `n` | Add a subscription; enter the name, then the masked URL |
| `u` | Refresh all subscriptions |
| `l` | Check latency for all servers |
| `c` | Connect using the current selection, mode, and route |
| `d` | Disconnect |
| `q` / `Ctrl+C` | Quit |

While entering a subscription, `Enter` advances or submits, `Backspace` edits, and `Esc` cancels. Connection-changing actions are ignored while another side effect is in progress.

## CLI reference

```text
tuibox subscription add <name> <url>
tuibox subscription list
tuibox subscription update [id]
tuibox subscription remove <id>
tuibox server list
tuibox server latency <id>
tuibox server latency --all
tuibox connect <endpoint-id|auto> --mode tun|proxy --route global|rule|direct
tuibox disconnect
tuibox status
tuibox telemetry enable
tuibox telemetry disable
tuibox telemetry status
tuibox doctor
tuibox update --check
tuibox update
tuibox version
tuibox completion bash|fish|powershell|zsh
```

Run `tuibox <command> --help` for generated usage. Usage errors exit with status `2`; operational failures exit with status `1`.

## Formats and protocols

### Subscription formats

- Newline-separated share-link/URI lists.
- Whole-document standard or URL-safe Base64, padded or unpadded.
- Clash YAML with a top-level `proxies` list.
- sing-box JSON with a top-level `outbounds` list.

### Endpoint protocols

- VLESS
- VMess
- Trojan
- Shadowsocks (`ss`)
- Hysteria2 (`hysteria2` or `hy2`)
- TUIC

VLESS, VMess, and Trojan support TCP, WebSocket, gRPC, and HTTPUpgrade transports when the imported fields map to TuiBox's normalized model. Unsupported or malformed entries are skipped with redacted warnings. A document with no valid endpoints is rejected, and a failed refresh preserves the previous endpoint cache.

Latency checks are TCP connection probes, not end-to-end proxy benchmarks. They support VLESS, VMess, Trojan, and Shadowsocks. Hysteria2 and TUIC are reported as `unsupported`.

## Connection and routing behavior

- **TUN**: sing-box runs under the root daemon and creates a TUN inbound with automatic, strict routing.
- **Proxy**: sing-box drops to the authenticated caller's UID/GID and listens only on `127.0.0.1:2080`.
- **Global**: the selected endpoint is the default outbound; private networks and local suffixes remain direct.
- **Rule**: currently behaves like Global plus internal direct-rule support. v0.1 exposes no user-facing rule editor.
- **Direct**: no proxy endpoint is sent to the daemon; the direct outbound is the default.

Generated core logging is disabled. DNS is currently fixed to direct UDP `1.1.1.1:53` with `prefer_ipv4`.

## Data and installed files

### User data

| Platform | State | Fallback secret file |
| --- | --- | --- |
| Linux | `${XDG_DATA_HOME:-$HOME/.local/share}/tuibox/state.json` | `${XDG_CONFIG_HOME:-$HOME/.config}/tuibox/secrets.json` |
| macOS | `$HOME/Library/Application Support/tuibox/state.json` | `$HOME/Library/Application Support/tuibox/secrets.json` |

User directories must be mode `0700`; state and fallback secret files must be regular mode-`0600` files. TuiBox rejects unsafe paths or permissions instead of silently weakening them. `state.json` contains subscription metadata and the normalized endpoint cache, including endpoint credentials. Subscription source URLs are stored separately in macOS Keychain or Linux Secret Service when the required OS tool is available; otherwise the fallback file is used and `tuibox doctor` reports a warning.

### System installation defaults

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/tuibox` | Symlink to the client |
| `/usr/local/libexec/tuibox/tuibox` | Client binary |
| `/usr/local/libexec/tuibox/tuiboxd` | Privileged daemon |
| `/usr/local/libexec/tuibox/tuibox-update-helper` | Privileged update helper |
| `/usr/local/libexec/tuibox/sing-box` | Pinned core binary |
| `/var/lib/tuibox` | Linux root-owned runtime configs, mode `0700` |
| `/run/tuibox/tuiboxd.sock` | Linux local RPC socket in a root-owned, user-group-readable mode-`0750` directory |
| `/private/var/db/tuibox` | macOS root-owned runtime configs, mode `0700` |
| `/private/var/run/tuibox/tuiboxd.sock` | macOS local RPC socket in a root-owned, user-group-readable mode-`0750` directory |
| `/etc/systemd/system/tuiboxd.service` | Linux service |
| `/Library/LaunchDaemons/io.github.rezraf.tuiboxd.plist` | macOS service |

The installer and uninstaller support environment overrides for packaging tests and custom layouts. Treat those overrides as advanced options; configured system paths must be absolute, and every existing ancestor touched with elevated privileges must be root-owned, non-symlink, and not group- or world-writable.

## Update

Check without changing files:

```sh
tuibox update --check
```

Apply the latest stable release:

```sh
tuibox update
```

The installed client first verifies that the helper and its parent chain are root-owned and non-writable, then delegates replacement through `/usr/bin/sudo`. The elevated helper independently revalidates the installed layout, re-fetches the selected stable release, verifies the archive checksum, validates the archive, stages same-filesystem replacements for the client, daemon, and helper, and attempts rollback if replacement fails.

Limitations of v0.1 updates:

- development builds cannot update;
- the updater does not update sing-box or service definitions;
- the updater does not restart the running daemon;
- checksums and archives are fetched from the same GitHub release trust domain;
- no artifact signature is verified.

After an applied update, restart the daemon:

Linux:

```sh
sudo systemctl restart tuiboxd.service
```

macOS:

```sh
sudo launchctl bootout system/io.github.rezraf.tuiboxd || true
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rezraf.tuiboxd.plist
sudo launchctl enable system/io.github.rezraf.tuiboxd
```

## Uninstall

From a checked-out source tree or extracted release directory:

```sh
sh uninstall.sh
```

This removes the known TuiBox binaries, service definition, and runtime socket, then removes installation/runtime directories only when they are empty. System state, user state, and unrelated files are preserved.

Remove state and fallback secret files too:

```sh
sh uninstall.sh --purge-state
```

Native Keychain or Secret Service entries are not deleted by `uninstall.sh`; remove them with the platform credential manager if required.

## Telemetry

Telemetry consent defaults to disabled:

```sh
tuibox telemetry status
tuibox telemetry enable
tuibox telemetry disable
```

In v0.1 these commands only persist consent. The application does not configure a telemetry endpoint or instantiate the sender, so enabling consent sends nothing. The closed event schema and transport safeguards are documented in [docs/telemetry.md](docs/telemetry.md).

## Troubleshooting

Start with:

```sh
tuibox doctor
```

It checks the supported OS, user state store, credential backend, and daemon health. Output is JSON; an error diagnostic makes the command fail.

### Daemon unavailable

Linux:

```sh
sudo systemctl status tuiboxd.service
```

macOS:

```sh
sudo launchctl print system/io.github.rezraf.tuiboxd
```

The macOS service writes startup output to `/var/log/tuiboxd.log`. Linux service output is managed by systemd.

### Access denied

The installer authorizes the invoking user's UID and sets the socket group to that user's primary group. A different local account is not authorized. Reinstall from the intended account rather than broadening socket permissions.

### State or secret backend unavailable

Verify that the user data/config directories are owned by you and mode `0700`, and that `state.json` or `secrets.json` are regular mode-`0600` files. TuiBox intentionally rejects symlinks and permissive files.

### No usable Auto Best server

Run `tuibox server latency --all`. Auto Best requires at least one successful TCP probe; Hysteria2 and TUIC cannot win because their latency probe is unsupported in v0.1.

### Update unavailable

`tuibox version` must report a stable release version, not `dev`. The updater also requires the standard installed layout and a regular executable root-owned helper.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability and [docs/security-model.md](docs/security-model.md) for trust boundaries, mitigations, and non-goals. Do not post subscription URLs, credentials, imported documents, RPC payloads, or raw sing-box output in public issues.

## Limitations

- Pre-release software with no compatibility guarantee for provider-specific fields.
- No Windows, GUI, mobile client, remote administration, multi-user orchestration, or load balancing.
- One daemon-managed connection session per machine.
- No user-facing custom route-rule editor in v0.1.
- Fixed proxy address `127.0.0.1:2080`, TUN interface/address, and direct DNS resolver.
- Imported `insecure`/`skip-cert-verify` settings are honored when valid; use only trusted subscriptions.
- Subscription HTTPS protects transport to the provider but does not make provider content trustworthy.
- Checksums detect accidental or unauthorized archive changes only relative to the fetched checksum file; they are not independent signatures.
- Native credential entries survive `uninstall.sh --purge-state`.
- Telemetry transmission is not wired in v0.1, even after consent is enabled.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [docs/architecture.md](docs/architecture.md).

## Corresponding source and licenses

The corresponding source for each TuiBox release is the repository tree at the same Git tag: `https://github.com/rezraf/tui-box/tree/<tag>`. Release archives include the project [LICENSE](LICENSE), this README, and [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). The notices file records the exact linked Go module inventory, each pinned version, its source location, and the applicable redistributed license text. Recipients can regenerate it from the pinned module graph with `sh scripts/generate-third-party-notices.sh THIRD_PARTY_NOTICES` in the corresponding source tree.

## License

TuiBox is licensed under [GNU GPL v3 only](LICENSE), SPDX identifier `GPL-3.0-only`.
