#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist_dir=${1:-$repo_dir/dist}
case $dist_dir in
  /*) ;;
  *) dist_dir=$(pwd)/$dist_dir ;;
esac

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
sh "$repo_dir/scripts/generate-third-party-notices.sh" "$temporary/THIRD_PARTY_NOTICES"
cmp "$temporary/THIRD_PARTY_NOTICES" "$repo_dir/THIRD_PARTY_NOTICES"

archive_count=0
for os_name in linux darwin; do
  for architecture in amd64 arm64; do
    archive=$dist_dir/tuibox_${os_name}_${architecture}.tar.gz
    test -f "$archive" || {
      printf 'missing release archive: %s\n' "$archive" >&2
      exit 1
    }
    archive_count=$((archive_count + 1))
    listing=$temporary/${os_name}-${architecture}.listing
    tar -tzf "$archive" >"$listing"
    for required in LICENSE THIRD_PARTY_NOTICES README.md scripts/stable-release.sh tuibox tuiboxd; do
      grep -Fx -- "$required" "$listing" >/dev/null || {
        printf '%s is missing from %s\n' "$required" "$archive" >&2
        exit 1
      }
    done
    tar -xOf "$archive" LICENSE >"$temporary/LICENSE"
    cmp "$temporary/LICENSE" "$repo_dir/LICENSE"
    tar -xOf "$archive" THIRD_PARTY_NOTICES >"$temporary/THIRD_PARTY_NOTICES.archive"
    cmp "$temporary/THIRD_PARTY_NOTICES.archive" "$repo_dir/THIRD_PARTY_NOTICES"
  done
done

test "$archive_count" -eq 4
printf 'release snapshot license inspection passed\n'
