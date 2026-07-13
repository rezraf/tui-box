# Verify TuiBox CLI

Build the client into a temporary directory, then exercise the real binary:

```sh
tmpdir=$(mktemp -d)
go build -o "$tmpdir/tuibox" ./cmd/tuibox
"$tmpdir/tuibox" --help
"$tmpdir/tuibox" version
"$tmpdir/tuibox"
```

For lazy-opening and exit-code probes, isolate user paths and use an invalid socket override:

```sh
HOME="$tmpdir/home" XDG_DATA_HOME="$tmpdir/data" XDG_CONFIG_HOME="$tmpdir/config" TUIBOX_SOCKET=relative.sock "$tmpdir/tuibox" --help
HOME="$tmpdir/home" XDG_DATA_HOME="$tmpdir/data" XDG_CONFIG_HOME="$tmpdir/config" "$tmpdir/tuibox" connect endpoint --mode invalid --route global
HOME="$tmpdir/home" XDG_DATA_HOME="$tmpdir/data" XDG_CONFIG_HOME="$tmpdir/config" TUIBOX_SOCKET=relative.sock "$tmpdir/tuibox" status
```

Expected exit codes: help/version `0`, usage errors `2`, operational failures `1`. Remove the temporary directory afterward.
