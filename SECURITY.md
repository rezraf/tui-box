# Security Policy

## Supported versions

TuiBox has not published a stable release. Security fixes are developed against the current `main` branch and will be included in the next release. Older snapshots are not guaranteed to receive backports.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability.

1. If this repository shows GitHub's **Report a vulnerability** button, use it to create a private vulnerability report.
2. If private vulnerability reporting is unavailable, contact the maintainer privately through a channel listed on the [maintainer's GitHub profile](https://github.com/rezraf).
3. Include the affected revision/version, platform, impact, reproduction steps, and the smallest safe proof of concept.
4. Remove subscription URLs, endpoint credentials, imported documents, access tokens, personal data, RPC payloads, and raw sing-box output.

You should receive an acknowledgement within 7 days. Triage, remediation, and disclosure timing depend on severity and maintainer availability. Please allow a reasonable remediation period before public disclosure.

If no private channel is available, report only that you have a security issue and request private contact. Do not publish exploit details.

## Scope

Reports are especially useful for:

- bypassing Unix-socket peer authorization;
- crossing the unprivileged-client/root-daemon boundary;
- arbitrary command, argument, environment, executable, or config-path injection;
- unsafe archive extraction or updater replacement;
- subscription URL or credential disclosure;
- symlink, ownership, or permission bypasses in state/runtime paths;
- malformed input causing memory exhaustion, hangs, or panics outside documented bounds;
- telemetry sending without explicit consent or sending fields outside the documented schema.

## Out of scope

Unless a TuiBox defect creates or amplifies the issue, the following are outside this project's security boundary:

- vulnerabilities in sing-box, the operating system, service manager, Keychain, Secret Service, GitHub, or a subscription provider;
- a host or root account already compromised;
- malicious traffic relays or provider endpoints;
- deanonymization, traffic-correlation, censorship-resistance, or privacy guarantees not provided by the underlying protocol/core;
- credentials intentionally imported from an untrusted subscription;
- denial of service requiring authorized local access and staying within documented resource limits.

Third-party vulnerabilities should be reported to the responsible upstream project. Do not send live credentials as evidence.

## Disclosure and fixes

Security fixes should include regression tests where practical. Release notes may withhold exploit details until users have had time to update. The release workflow creates SHA-256 checksums and build-provenance attestations, but TuiBox does not currently publish or verify cryptographic artifact signatures.

See [docs/security-model.md](docs/security-model.md) for the implemented trust boundaries and known limitations.
