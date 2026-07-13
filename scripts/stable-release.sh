#!/bin/sh
set -eu

fail() {
  printf 'stable release selection failed: %s\n' "$1" >&2
  exit 1
}

mode=${1:-}
case $mode in
  highest)
    candidate=
    shift
    ;;
  require-newer)
    test "$#" -ge 2 || fail 'require-newer needs a candidate tag and release metadata'
    candidate=$2
    shift 2
    ;;
  *) fail 'expected highest or require-newer mode' ;;
esac

test "$#" -gt 0 || fail 'release metadata is required'
command -v jq >/dev/null 2>&1 || fail 'jq is required'

jq -ser --arg mode "$mode" --arg candidate "$candidate" '
  def version_record:
    . as $tag
    | capture("^v(?<major>0|[1-9][0-9]*)\\.(?<minor>0|[1-9][0-9]*)\\.(?<patch>0|[1-9][0-9]*)$")
    | {
        tag: $tag,
        key: [
          (.major | length), .major,
          (.minor | length), .minor,
          (.patch | length), .patch
        ]
      };
  def published_stable_versions:
    .[]
    | if type == "array" then .[] else error("release metadata page must be an array") end
    | select(
        type == "object"
        and .draft == false
        and .prerelease == false
        and (.tag_name | type) == "string"
        and (.tag_name | test("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"))
      )
    | .tag_name
    | version_record;
  [published_stable_versions] as $versions
  | ($versions | if length == 0 then null else max_by(.key) end) as $highest
  | if $mode == "highest" then
      if $highest == null then error("no published stable semantic release") else $highest.tag end
    else
      ($candidate | version_record) as $requested
      | if $highest == null or $requested.key > $highest.key then
          $requested.tag
        else
          error("candidate release is not newer than the highest published stable release")
        end
    end
' "$@"
