## Outcome

Describe the user-visible result or defect fixed.

## Implementation

Explain the smallest relevant design change and any tradeoffs.

## Security and compatibility

- Trust boundary or privilege impact:
- New/changed untrusted input:
- Data, credential, logging, or telemetry impact:
- Format, platform, CLI, TUI, RPC, install, or update compatibility impact:

## Verification

List exact commands and observed results.

```text
<commands and concise results>
```

## Checklist

- [ ] The change is focused and includes regression coverage where practical.
- [ ] `go test ./...` passes.
- [ ] `go test -race ./...` passes for code changes.
- [ ] `go vet ./...` passes for Go changes.
- [ ] Both binaries build, and affected shell scripts pass `sh -n`.
- [ ] Public docs match command help, TUI controls, paths, formats, security, telemetry, and release behavior.
- [ ] No subscription URL, credential, token, imported document, personal data, RPC payload, raw core output, local cache, or machine-specific path is included.
- [ ] `git diff --check` passes.
