#!/bin/sh
set -eu

output=${1:-THIRD_PARTY_NOTICES}
case $output in
  /*) ;;
  *) output=$(pwd)/$output ;;
esac

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
(cd "$repo_dir" && go run ./scripts/cmd/generate-notices -output "$output")
