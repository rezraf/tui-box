#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
selector=$repo_dir/scripts/stable-release.sh
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

cat >"$work_dir/page-1.json" <<'JSON'
[
  {"tag_name":"v99.0.0","draft":true,"prerelease":false},
  {"tag_name":"v88.0.0","draft":false,"prerelease":true},
  {"tag_name":"v01.0.0","draft":false,"prerelease":false},
  {"tag_name":"v0.9.0","draft":false,"prerelease":false},
  {"tag_name":"v100.0.0","draft":false}
]
JSON
cat >"$work_dir/page-2.json" <<'JSON'
[
  {"tag_name":"v0.10.0","draft":false,"prerelease":false},
  {"tag_name":"not-a-version","draft":false,"prerelease":false}
]
JSON

selected=$(sh "$selector" highest "$work_dir/page-1.json" "$work_dir/page-2.json")
test "$selected" = v0.10.0 || {
  printf 'highest stable release = %s, want v0.10.0\n' "$selected" >&2
  exit 1
}

sh "$selector" require-newer v0.11.0 "$work_dir/page-1.json" "$work_dir/page-2.json" >/dev/null
for rejected in v0.10.0 v0.8.9 v0.10.0-rc.1 v00.11.0; do
  if sh "$selector" require-newer "$rejected" "$work_dir/page-1.json" "$work_dir/page-2.json" >/dev/null 2>&1; then
    printf 'non-monotonic or invalid release was accepted: %s\n' "$rejected" >&2
    exit 1
  fi
done

cat >"$work_dir/large.json" <<'JSON'
[
  {"tag_name":"v999999999999999999999.0.0","draft":false,"prerelease":false},
  {"tag_name":"v1000000000000000000000.0.0","draft":false,"prerelease":false}
]
JSON
selected=$(sh "$selector" highest "$work_dir/large.json")
test "$selected" = v1000000000000000000000.0.0 || {
  printf 'large semantic versions were compared incorrectly: %s\n' "$selected" >&2
  exit 1
}

printf '%s\n' '[{"tag_name":"v1.0.0","draft":true,"prerelease":false}]' >"$work_dir/no-stable.json"
if sh "$selector" highest "$work_dir/no-stable.json" >/dev/null 2>&1; then
  printf 'selector accepted metadata without a published stable release\n' >&2
  exit 1
fi

printf '%s\n' '{"tag_name":"v1.0.0","draft":false,"prerelease":false}' >"$work_dir/not-an-array.json"
if sh "$selector" highest "$work_dir/not-an-array.json" >/dev/null 2>&1; then
  printf 'selector accepted a non-array release response\n' >&2
  exit 1
fi

printf 'stable release selector tests passed\n'
