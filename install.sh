#!/bin/sh
set -eu
umask 077

core_version=1.13.14
repository=rezraf/tui-box
max_archive_bytes=104857600
max_checksum_bytes=1048576
max_release_metadata_bytes=2097152
max_release_pages=10
max_binary_bytes=67108864
max_service_bytes=1048576
test_mode=${TUIBOX_TEST_MODE:-0}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release_selector=$script_dir/scripts/stable-release.sh

fail() {
  printf 'TuiBox install failed: %s\n' "$1" >&2
  exit 1
}

valid_path() {
  case $1 in
    /) return 1 ;;
    /*) ;;
    *) return 1 ;;
  esac
  case $1 in
    *[!A-Za-z0-9_./-]*|*//*|*/|*/../*|*/..|*/./*|*/.) return 1 ;;
  esac
  return 0
}

valid_identity() {
  case $1 in
    ''|*[!0-9]*) return 1 ;;
  esac
  test "$1" -lt 4294967295
}

directory_uid() {
  if value=$(stat -f '%u' "$1" 2>/dev/null); then
    printf '%s\n' "$value"
    return
  fi
  stat -c '%u' "$1"
}

directory_mode() {
  if value=$(stat -f '%OLp' "$1" 2>/dev/null); then
    printf '%s\n' "$value"
    return
  fi
  stat -c '%a' "$1"
}

directory_gid() {
  if value=$(stat -f '%g' "$1" 2>/dev/null); then
    printf '%s\n' "$value"
    return
  fi
  stat -c '%g' "$1"
}

trusted_parent_chain() {
  path=$1
  allowed_uid=$2
  trusted_root=$3
  if test "$trusted_root" != /; then
    case $path in
      "$trusted_root"|"$trusted_root"/*) ;;
      *) return 1 ;;
    esac
  fi
  while test ! -e "$path" && test ! -L "$path"; do
    parent=${path%/*}
    test -n "$parent" || parent=/
    test "$parent" != "$path" || return 1
    path=$parent
  done
  while :; do
    test -d "$path" && test ! -L "$path" || return 1
    uid=$(directory_uid "$path") || return 1
    mode=$(directory_mode "$path") || return 1
    if test "$uid" -ne 0 && test "$uid" -ne "$allowed_uid"; then
      return 1
    fi
    permissions=$((mode % 100))
    group_digit=$((permissions / 10))
    other_digit=$((permissions % 10))
    case $group_digit$other_digit in
      [2367]?|?[2367]) return 1 ;;
    esac
    test "$path" = "$trusted_root" && return 0
    parent=${path%/*}
    test -n "$parent" || parent=/
    test "$parent" != "$path" || return 1
    path=$parent
  done
}

valid_version() {
  printf '%s\n' "$1" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
}

detect_platform() {
  if test "$test_mode" = 1; then
    os_name=${TUIBOX_OS:-}
    machine=${TUIBOX_ARCH:-}
  else
    case $(uname -s) in
      Linux) os_name=linux ;;
      Darwin) os_name=darwin ;;
      *) fail 'unsupported operating system' ;;
    esac
    machine=$(uname -m)
  fi
  case $os_name in
    linux|darwin) ;;
    *) fail 'unsupported operating system' ;;
  esac
  case $machine in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'unsupported architecture' ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail 'no SHA-256 tool is available'
  fi
}

file_link_count() {
  if count=$(stat -f '%l' "$1" 2>/dev/null); then
    printf '%s\n' "$count"
    return
  fi
  stat -c '%h' "$1"
}

valid_payload_file() {
  path=$1
  maximum_bytes=$2
  test -f "$path" && test ! -L "$path" || return 1
  test "$(file_link_count "$path")" -eq 1 || return 1
  size=$(wc -c <"$path")
  test "$size" -gt 0 && test "$size" -le "$maximum_bytes"
}

download_https() {
  destination=$1
  source_url=$2
  maximum_bytes=$3
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-redirs 5 --connect-timeout 10 --max-time 120 --retry 2 \
    --max-filesize "$maximum_bytes" \
    --output "$destination" "$source_url" || fail 'download failed'
  size=$(wc -c <"$destination")
  test "$size" -le "$maximum_bytes" || fail 'download exceeds the size limit'
}

resolve_release_version() {
  release_metadata_pages=$1
  command -v jq >/dev/null 2>&1 || fail 'jq is required to resolve the latest stable release'
  test -f "$release_selector" && test ! -L "$release_selector" || fail 'stable release selector is unavailable'
  : >"$release_metadata_pages"
  release_page=1
  while test "$release_page" -le "$max_release_pages"; do
    release_metadata=$work_dir/releases-$release_page.json
    release_metadata_url="https://api.github.com/repos/$repository/releases?per_page=100&page=$release_page"
    download_https "$release_metadata" "$release_metadata_url" "$max_release_metadata_bytes"
    release_count=$(jq -er 'if type == "array" then length else error("release metadata page must be an array") end' "$release_metadata") || fail 'release metadata is invalid'
    jq -c . "$release_metadata" >>"$release_metadata_pages" || fail 'release metadata is invalid'
    if test "$release_count" -lt 100; then
      sh "$release_selector" highest "$release_metadata_pages" || fail 'no published stable release is available'
      return
    fi
    release_page=$((release_page + 1))
  done
  fail 'release metadata exceeds the pagination limit'
}

checksum_for_asset() {
  checksum_file=$1
  asset_name=$2
  found=
  while IFS=' ' read -r digest remainder; do
    test -n "$digest" || continue
    name=$(printf '%s\n' "$remainder" | tr -d ' ')
    case $digest in
      *[!0-9A-Fa-f]*|'') fail 'release checksum file is invalid' ;;
    esac
    test "${#digest}" -eq 64 || fail 'release checksum file is invalid'
    if test "$name" = "$asset_name"; then
      test -z "$found" || fail 'release checksum is duplicated'
      found=$(printf '%s' "$digest" | tr 'A-F' 'a-f')
    fi
  done <"$checksum_file"
  test -n "$found" || fail 'release checksum is missing'
  printf '%s\n' "$found"
}

verify_digest() {
  file=$1
  expected=$(printf '%s' "$2" | tr 'A-F' 'a-f')
  actual=$(sha256_file "$file")
  test "$actual" = "$expected" || fail 'SHA-256 verification failed'
}

safe_archive_listing() {
  archive=$1
  tar -tzf "$archive" | while IFS= read -r entry; do
    case $entry in
      ''|/*|../*|*/../*|*/..) exit 1 ;;
    esac
  done || fail 'archive contains an unsafe path'
}

extract_release() {
  archive=$1
  destination=$2
  safe_archive_listing "$archive"
  if test "$test_mode" = 1; then
    tar -xzf "$archive" -C "$destination" tuibox tuiboxd || fail 'release extraction failed'
  else
    tar -xzf "$archive" -C "$destination" \
      tuibox tuiboxd \
      packaging/systemd/tuiboxd.service \
      packaging/launchd/io.github.rezraf.tuiboxd.plist || fail 'release extraction failed'
  fi
  for binary in tuibox tuiboxd; do
    valid_payload_file "$destination/$binary" "$max_binary_bytes" || fail 'release binary is invalid'
    chmod 755 "$destination/$binary"
  done
}

extract_core() {
  archive=$1
  destination=$2
  directory=sing-box-$core_version-$os_name-$arch
  safe_archive_listing "$archive"
  tar -xzf "$archive" -C "$destination" "$directory/sing-box" || fail 'core extraction failed'
  core_path=$destination/$directory/sing-box
  valid_payload_file "$core_path" "$max_binary_bytes" || fail 'core binary is invalid'
  chmod 755 "$core_path"
}

as_root() {
  if test "$test_mode" = 1 || test "$(id -u)" -eq 0; then
    "$@"
  else
    /usr/bin/sudo -- "$@"
  fi
}

install_directory() {
  mode=$1
  path=$2
  group=${3:-$root_group}
  if test "$test_mode" = 1; then
    install -d -m "$mode" "$path"
  else
    as_root install -d -m "$mode" -o root -g "$group" "$path"
  fi
}

validate_installed_directory() {
  path=$1
  expected_mode=$2
  expected_uid=$3
  expected_gid=$4
  test -d "$path" && test ! -L "$path" || return 1
  test "$(directory_mode "$path")" -eq "$expected_mode" || return 1
  test "$(directory_uid "$path")" -eq "$expected_uid" || return 1
  test "$(directory_gid "$path")" -eq "$expected_gid"
}

path_exists() {
  test -e "$1" || test -L "$1"
}

secure_mode() {
  mode=$1
  permissions=$((mode % 100))
  group_digit=$((permissions / 10))
  other_digit=$((permissions % 10))
  case $group_digit$other_digit in
    [2367]?|?[2367]) return 1 ;;
  esac
  return 0
}

validate_owned_directory() {
  path=$1
  expected_uid=$2
  test -d "$path" && test ! -L "$path" || return 1
  test "$(directory_uid "$path")" -eq "$expected_uid" || return 1
  secure_mode "$(directory_mode "$path")"
}

validate_managed_file() {
  path=$1
  expected_mode=$2
  expected_uid=$3
  expected_gid=$4
  maximum_bytes=$5
  valid_payload_file "$path" "$maximum_bytes" || return 1
  test "$(directory_mode "$path")" -eq "$expected_mode" || return 1
  test "$(directory_uid "$path")" -eq "$expected_uid" || return 1
  test "$(directory_gid "$path")" -eq "$expected_gid"
}

install_file() {
  mode=$1
  source=$2
  destination=$3
  if test "$test_mode" = 1; then
    install -m "$mode" "$source" "$destination"
  else
    as_root install -m "$mode" -o root -g "$root_group" "$source" "$destination"
  fi
}

render_service() {
  template=$1
  destination=$2
  sed \
    -e "s|@TUIBOX_DAEMON@|$daemon_path|g" \
    -e "s|@TUIBOX_CORE@|$installed_core_path|g" \
    -e "s|@TUIBOX_STATE_DIR@|$state_dir|g" \
    -e "s|@TUIBOX_RUN_DIR@|$run_dir|g" \
    -e "s|@TUIBOX_SOCKET@|$socket_path|g" \
    -e "s|@TUIBOX_GID@|$install_gid|g" \
    -e "s|@TUIBOX_UID@|$install_uid|g" \
    "$template" >"$destination"
}

validate_service_template() {
  service_template=$1
  valid_payload_file "$service_template" "$max_service_bytes" || return 1
  for token in \
    @TUIBOX_DAEMON@ \
    @TUIBOX_CORE@ \
    @TUIBOX_STATE_DIR@ \
    @TUIBOX_SOCKET@ \
    @TUIBOX_GID@ \
    @TUIBOX_UID@
  do
    grep -F -- "$token" "$service_template" >/dev/null || return 1
  done
  if test "$os_name" = linux; then
    grep -F -- '@TUIBOX_RUN_DIR@' "$service_template" >/dev/null || return 1
    grep -Fx -- '[Service]' "$service_template" >/dev/null || return 1
    grep -F -- 'ExecStart=@TUIBOX_DAEMON@ --core @TUIBOX_CORE@' "$service_template" >/dev/null || return 1
    return 0
  fi
  grep -F -- '<string>io.github.rezraf.tuiboxd</string>' "$service_template" >/dev/null || return 1
  grep -F -- '<key>ProgramArguments</key>' "$service_template" >/dev/null
}

prepare_service() {
  if test "$os_name" = linux; then
    service_template=$extract_dir/packaging/systemd/tuiboxd.service
    test -f "$service_template" || service_template=$script_dir/packaging/systemd/tuiboxd.service
    rendered_service=$work_dir/tuiboxd.service
  else
    service_template=$extract_dir/packaging/launchd/io.github.rezraf.tuiboxd.plist
    test -f "$service_template" || service_template=$script_dir/packaging/launchd/io.github.rezraf.tuiboxd.plist
    rendered_service=$work_dir/io.github.rezraf.tuiboxd.plist
  fi
  if test "$test_mode" = 1 && test -n "${TUIBOX_TEST_SERVICE_TEMPLATE:-}"; then
    service_template=$TUIBOX_TEST_SERVICE_TEMPLATE
  fi
  validate_service_template "$service_template" || fail 'service template is invalid'
  render_service "$service_template" "$rendered_service"
  valid_payload_file "$rendered_service" "$max_service_bytes" || fail 'rendered service is invalid'
  if grep -Eq '@TUIBOX_[A-Z0-9_]+@' "$rendered_service"; then
    fail 'rendered service contains an unresolved placeholder'
  fi
  if test "$os_name" = linux; then
    expected_exec="ExecStart=$daemon_path --core $installed_core_path --runtime-dir $state_dir --socket $socket_path --socket-gid $install_gid --allow-uid $install_uid"
    grep -Fx -- "$expected_exec" "$rendered_service" >/dev/null || fail 'rendered systemd service is invalid'
    grep -Fx -- 'User=root' "$rendered_service" >/dev/null || fail 'rendered systemd service is invalid'
    grep -Fx -- 'Group=root' "$rendered_service" >/dev/null || fail 'rendered systemd service is invalid'
    return
  fi
  for value in \
    io.github.rezraf.tuiboxd \
    "$daemon_path" \
    "$installed_core_path" \
    "$state_dir" \
    "$socket_path" \
    "$install_gid" \
    "$install_uid"
  do
    grep -F -- "<string>$value</string>" "$rendered_service" >/dev/null || fail 'rendered launchd service is invalid'
  done
}

find_service_manager() {
  if test "$test_mode" = 1; then
    service_manager=${TUIBOX_TEST_SERVICE_MANAGER:-}
  elif test "$os_name" = linux; then
    service_manager=$(command -v systemctl 2>/dev/null || true)
  else
    service_manager=$(command -v launchctl 2>/dev/null || true)
  fi
  valid_path "$service_manager" || fail 'service manager is unavailable'
  test -f "$service_manager" && test ! -L "$service_manager" && test -x "$service_manager" || fail 'service manager is unavailable'
  expected_manager_uid=$installed_uid
  test "$(directory_uid "$service_manager")" -eq "$expected_manager_uid" || fail 'service manager ownership is invalid'
  secure_mode "$(directory_mode "$service_manager")" || fail 'service manager permissions are invalid'
  service_manager_parent=${service_manager%/*}
  test -n "$service_manager_parent" || service_manager_parent=/
  trusted_parent_chain "$service_manager_parent" "$trust_uid" "$trust_root" || fail 'service manager path is unsafe'
}

run_service_manager() {
  as_root "$service_manager" "$@"
}

paths_overlap() {
  first_path=$1
  second_path=$2
  case $first_path in
    "$second_path"|"$second_path"/*) return 0 ;;
  esac
  case $second_path in
    "$first_path"/*) return 0 ;;
  esac
  return 1
}

validate_destination_layout() {
  for path_pair in \
    "$libexec_dir|$bin_dir" \
    "$libexec_dir|$state_dir" \
    "$libexec_dir|$run_dir" \
    "$libexec_dir|$service_dir" \
    "$bin_dir|$state_dir" \
    "$bin_dir|$run_dir" \
    "$bin_dir|$service_dir" \
    "$state_dir|$run_dir" \
    "$state_dir|$service_dir" \
    "$run_dir|$service_dir"
  do
    first_path=${path_pair%%|*}
    second_path=${path_pair#*|}
    paths_overlap "$first_path" "$second_path" && fail 'managed installation paths overlap'
  done
  return 0
}

validate_existing_installation() {
  validate_managed_file "$client_path" 755 "$installed_uid" "$root_gid" "$max_binary_bytes" || return 1
  validate_managed_file "$daemon_path" 755 "$installed_uid" "$root_gid" "$max_binary_bytes" || return 1
  validate_managed_file "$helper_path" 755 "$installed_uid" "$root_gid" "$max_binary_bytes" || return 1
  validate_managed_file "$installed_core_path" 755 "$installed_uid" "$root_gid" "$max_binary_bytes" || return 1
  validate_managed_file "$service_path" 644 "$installed_uid" "$root_gid" "$max_service_bytes" || return 1
  test -L "$launcher_path" || return 1
  test "$(readlink "$launcher_path")" = "$client_path" || return 1
  cmp "$client_path" "$helper_path" >/dev/null || return 1
  cmp "$service_path" "$rendered_service" >/dev/null
}

preflight_destinations() {
  for managed_directory in \
    "$prefix" \
    "$prefix/libexec" \
    "$libexec_dir" \
    "$bin_dir" \
    "$state_dir" \
    "$run_dir" \
    "$service_dir"
  do
    if path_exists "$managed_directory"; then
      validate_owned_directory "$managed_directory" "$installed_uid" || fail 'managed directory is invalid'
    fi
  done
  if path_exists "$state_dir"; then
    validate_installed_directory "$state_dir" 0700 "$installed_uid" "$root_gid" || fail 'state directory permissions are invalid'
  fi
  if path_exists "$run_dir"; then
    validate_installed_directory "$run_dir" 0750 "$installed_uid" "$install_gid" || fail 'runtime directory permissions are invalid'
  fi

  managed_count=0
  for managed_path in \
    "$client_path" \
    "$daemon_path" \
    "$helper_path" \
    "$installed_core_path" \
    "$launcher_path" \
    "$service_path"
  do
    if path_exists "$managed_path"; then
      managed_count=$((managed_count + 1))
    fi
  done
  case $managed_count in
    0) existing_installation=0 ;;
    6)
      validate_existing_installation || fail 'pre-existing managed path is not a known TuiBox installation'
      existing_installation=1
      ;;
    *) fail 'pre-existing managed path collision detected' ;;
  esac

  if path_exists "$socket_path"; then
    if test "$existing_installation" != 1 || test ! -S "$socket_path" || test -L "$socket_path"; then
      fail 'runtime socket path collision detected'
    fi
  fi
  return 0
}

record_created_directory() {
  printf '%s\n' "$1" >>"$created_directories"
}

ensure_directory() {
  requested_mode=$1
  requested_path=$2
  requested_group=${3:-$root_group}
  if path_exists "$requested_path"; then
    return
  fi
  record_created_directory "$requested_path"
  install_directory "$requested_mode" "$requested_path" "$requested_group"
}

reserve_destination_path() {
  target_path=$1
  reservation_kind=$2
  target_directory=${target_path%/*}
  target_name=${target_path##*/}
  reserved_path=$(as_root mktemp "$target_directory/.tuibox-$reservation_kind.$target_name.XXXXXX") || fail 'could not reserve a transaction path'
  printf '%s\n' "$reserved_path" >>"$temporary_paths"
  printf '%s\n' "$reserved_path"
}

record_transaction_path() {
  printf '%s|%s|%s\n' "$1" "$2" "$3" >>"$transaction_paths"
}

stage_regular_file() {
  source_path=$1
  target_path=$2
  target_mode=$3
  maximum_bytes=$4
  staged_path=$(reserve_destination_path "$target_path" stage)
  backup_path=-
  if test "$existing_installation" = 1; then
    backup_path=$(reserve_destination_path "$target_path" backup)
  fi
  record_transaction_path "$target_path" "$staged_path" "$backup_path"
  install_file "$target_mode" "$source_path" "$staged_path"
  validate_managed_file "$staged_path" "$target_mode" "$installed_uid" "$root_gid" "$maximum_bytes" || fail 'staged managed file is invalid'
  cmp "$source_path" "$staged_path" >/dev/null || fail 'staged managed file differs from its source'
}

stage_launcher() {
  staged_path=$(reserve_destination_path "$launcher_path" stage)
  backup_path=-
  if test "$existing_installation" = 1; then
    backup_path=$(reserve_destination_path "$launcher_path" backup)
  fi
  record_transaction_path "$launcher_path" "$staged_path" "$backup_path"
  as_root rm -f "$staged_path"
  as_root ln -s "$client_path" "$staged_path"
  test -L "$staged_path" && test "$(readlink "$staged_path")" = "$client_path" || fail 'staged launcher is invalid'
}

validate_new_target() {
  installed_target=$1
  case $installed_target in
    "$client_path") source_path=$extract_dir/tuibox; target_mode=755; maximum_bytes=$max_binary_bytes ;;
    "$daemon_path") source_path=$extract_dir/tuiboxd; target_mode=755; maximum_bytes=$max_binary_bytes ;;
    "$helper_path") source_path=$extract_dir/tuibox; target_mode=755; maximum_bytes=$max_binary_bytes ;;
    "$installed_core_path") source_path=$core_path; target_mode=755; maximum_bytes=$max_binary_bytes ;;
    "$service_path") source_path=$rendered_service; target_mode=644; maximum_bytes=$max_service_bytes ;;
    "$launcher_path")
      test -L "$installed_target" && test "$(readlink "$installed_target")" = "$client_path"
      return
      ;;
    *) return 1 ;;
  esac
  validate_managed_file "$installed_target" "$target_mode" "$installed_uid" "$root_gid" "$maximum_bytes" || return 1
  cmp "$source_path" "$installed_target" >/dev/null
}

swap_staged_paths() {
  if test "$existing_installation" = 1; then
    validate_existing_installation || fail 'managed installation changed during staging'
  fi
  while IFS='|' read -r target_path staged_path backup_path; do
    test -n "$target_path" || continue
    if test "$existing_installation" = 1; then
      as_root mv -f "$target_path" "$backup_path" || fail 'could not back up an installed path'
    else
      path_exists "$target_path" && fail 'managed destination changed during staging'
    fi
    as_root mv -f "$staged_path" "$target_path" || fail 'could not atomically install a managed path'
    validate_new_target "$target_path" || fail 'installed managed path validation failed'
  done <"$transaction_paths"
}

activate_service() {
  service_attempted=1
  if test "$os_name" = linux; then
    run_service_manager daemon-reload || fail 'systemd daemon reload failed'
    run_service_manager enable --now tuiboxd.service || fail 'systemd service activation failed'
    return
  fi
  run_service_manager bootout system/io.github.rezraf.tuiboxd >/dev/null 2>&1 || true
  run_service_manager bootstrap system "$service_path" || fail 'launchd service activation failed'
  run_service_manager enable system/io.github.rezraf.tuiboxd || fail 'launchd service enablement failed'
}

quiesce_service_for_rollback() {
  test "$service_attempted" = 1 || return 0
  if test "$os_name" = linux; then
    if test "$existing_installation" = 1; then
      run_service_manager stop tuiboxd.service >/dev/null 2>&1
    else
      run_service_manager disable --now tuiboxd.service >/dev/null 2>&1
    fi
    return
  fi
  run_service_manager bootout system/io.github.rezraf.tuiboxd >/dev/null 2>&1
}

restore_service_after_rollback() {
  test "$service_attempted" = 1 || return 0
  if test "$os_name" = linux; then
    run_service_manager daemon-reload >/dev/null 2>&1 || return 1
    if test "$existing_installation" = 1; then
      run_service_manager enable --now tuiboxd.service >/dev/null 2>&1 || return 1
      run_service_manager restart tuiboxd.service >/dev/null 2>&1 || return 1
    fi
    return 0
  fi
  if test "$existing_installation" = 1; then
    run_service_manager bootstrap system "$service_path" >/dev/null 2>&1 || return 1
    run_service_manager enable system/io.github.rezraf.tuiboxd >/dev/null 2>&1 || return 1
  fi
  return 0
}

rollback_managed_paths() {
  rollback_failed=0
  while IFS='|' read -r target_path staged_path backup_path; do
    test -n "$target_path" || continue
    if test "$backup_path" != - && { test -L "$backup_path" || test -s "$backup_path"; }; then
      as_root mv -f "$backup_path" "$target_path" || rollback_failed=1
    elif test "$backup_path" = -; then
      if path_exists "$target_path"; then
        as_root rm -f "$target_path" || rollback_failed=1
      fi
    else
      as_root rm -f "$backup_path" >/dev/null 2>&1 || rollback_failed=1
    fi
    if path_exists "$staged_path"; then
      as_root rm -f "$staged_path" || rollback_failed=1
    fi
  done <"$transaction_paths"
  if test "$existing_installation" = 1; then
    validate_existing_installation || rollback_failed=1
  fi
  return "$rollback_failed"
}

cleanup_uncommitted_temporary_paths() {
  while IFS= read -r temporary_path; do
    test -n "$temporary_path" || continue
    if test -L "$temporary_path" || test -s "$temporary_path"; then
      case ${temporary_path##*/} in
        .tuibox-backup.*) continue ;;
      esac
    fi
    if path_exists "$temporary_path"; then
      as_root rm -f "$temporary_path" >/dev/null 2>&1 || true
    fi
  done <"$temporary_paths"
}

cleanup_committed_temporary_paths() {
  cleanup_failed=0
  while IFS= read -r temporary_path; do
    test -n "$temporary_path" || continue
    if path_exists "$temporary_path"; then
      as_root rm -f "$temporary_path" || cleanup_failed=1
    fi
  done <"$temporary_paths"
  return "$cleanup_failed"
}

rollback_created_directories() {
  directory_passes=$(wc -l <"$created_directories")
  directory_passes=$((directory_passes + 1))
  while test "$directory_passes" -gt 0; do
    while IFS= read -r created_directory; do
      test -n "$created_directory" || continue
      if path_exists "$created_directory"; then
        as_root rmdir "$created_directory" >/dev/null 2>&1 || true
      fi
    done <"$created_directories"
    directory_passes=$((directory_passes - 1))
  done
}

cleanup_install() {
  install_status=$1
  trap - EXIT HUP INT TERM
  if test "$transaction_active" = 1 && test "$transaction_committed" != 1; then
    rollback_incomplete=0
    quiesce_service_for_rollback || rollback_incomplete=1
    rollback_managed_paths || rollback_incomplete=1
    if test "$existing_installation" != 1 && path_exists "$socket_path"; then
      as_root rm -f "$socket_path" >/dev/null 2>&1 || rollback_incomplete=1
    fi
    restore_service_after_rollback || rollback_incomplete=1
    cleanup_uncommitted_temporary_paths
    rollback_created_directories
    if test "$rollback_incomplete" = 1; then
      printf 'TuiBox install rollback was incomplete; recoverable backups were preserved beside their targets.\n' >&2
      install_status=1
    fi
  fi
  rm -rf "$work_dir"
  exit "$install_status"
}

detect_platform
linux_state_default=/var/lib/tuibox
linux_run_default=/run/tuibox
darwin_state_default=/private/var/db/tuibox
darwin_run_default=/private/var/run/tuibox
if test "$os_name" = linux; then
  state_default=$linux_state_default
  run_default=$linux_run_default
else
  state_default=$darwin_state_default
  run_default=$darwin_run_default
fi
prefix=${TUIBOX_PREFIX:-/usr/local}
etc_dir=${TUIBOX_ETC_DIR:-/etc}
state_dir=${TUIBOX_STATE_DIR:-$state_default}
run_dir=${TUIBOX_RUN_DIR:-$run_default}
systemd_dir=${TUIBOX_SYSTEMD_DIR:-/etc/systemd/system}
launchd_dir=${TUIBOX_LAUNCHD_DIR:-/Library/LaunchDaemons}
release_version=${TUIBOX_VERSION:-}
for configured_path in "$prefix" "$etc_dir" "$state_dir" "$run_dir" "$systemd_dir" "$launchd_dir"; do
  valid_path "$configured_path" || fail 'configured path is invalid'
done
if test -n "$release_version"; then
  valid_version "$release_version" || fail 'release version is invalid'
fi

if test "$test_mode" = 1; then
  install_uid=${TUIBOX_UID:-1000}
  install_gid=${TUIBOX_GID:-1000}
else
  install_uid=${SUDO_UID:-$(id -u)}
  install_gid=${SUDO_GID:-$(id -g)}
fi
valid_identity "$install_uid" || fail 'install UID is invalid'
valid_identity "$install_gid" || fail 'install GID is invalid'

if test "$test_mode" = 1; then
  trust_root=${TUIBOX_TEST_TRUST_ROOT:-}
  if test "$trust_root" != /; then
    valid_path "$trust_root" || fail 'test trust root is invalid'
  fi
  trust_uid=$(id -u)
else
  trust_root=/
  trust_uid=0
fi
if test "$os_name" = linux; then
  trust_paths="$prefix $prefix/bin $prefix/libexec/tuibox $state_dir $run_dir $systemd_dir"
else
  trust_paths="$prefix $prefix/bin $prefix/libexec/tuibox $state_dir $run_dir $launchd_dir"
fi
for trusted_path in $trust_paths; do
  trusted_parent_chain "$trusted_path" "$trust_uid" "$trust_root" || fail 'installation path has an unsafe ancestor'
done

if test "$os_name" = darwin; then
  root_group=wheel
else
  root_group=root
fi
if test "$test_mode" = 1; then
  installed_uid=$(id -u)
  root_gid=$(id -g)
else
  installed_uid=0
  root_gid=0
fi

libexec_dir=$prefix/libexec/tuibox
bin_dir=$prefix/bin
client_path=$libexec_dir/tuibox
daemon_path=$libexec_dir/tuiboxd
helper_path=$libexec_dir/tuibox-update-helper
installed_core_path=$libexec_dir/sing-box
launcher_path=$bin_dir/tuibox
socket_path=$run_dir/tuiboxd.sock
if test "$os_name" = linux; then
  service_dir=$systemd_dir
  service_path=$service_dir/tuiboxd.service
else
  service_dir=$launchd_dir
  service_path=$service_dir/io.github.rezraf.tuiboxd.plist
fi
for install_path in \
  "$prefix/libexec" \
  "$libexec_dir" \
  "$bin_dir" \
  "$client_path" \
  "$daemon_path" \
  "$helper_path" \
  "$installed_core_path" \
  "$launcher_path" \
  "$socket_path" \
  "$service_path"
do
  valid_path "$install_path" || fail 'installation path is invalid'
done
validate_destination_layout

test_fail_after_service=0
if test "$test_mode" = 1; then
  test_fail_after_service=${TUIBOX_TEST_FAIL_AFTER_SERVICE:-0}
  case $test_fail_after_service in
    0|1) ;;
    *) fail 'test failure injection setting is invalid' ;;
  esac
fi

work_dir=$(mktemp -d)
transaction_active=0
transaction_committed=0
service_attempted=0
existing_installation=0
transaction_paths=$work_dir/transaction-paths
temporary_paths=$work_dir/temporary-paths
created_directories=$work_dir/created-directories
: >"$transaction_paths"
: >"$temporary_paths"
: >"$created_directories"
trap 'cleanup_install $?' EXIT
trap 'exit 1' HUP INT TERM
extract_dir=$work_dir/release
core_extract_dir=$work_dir/core
mkdir -p "$extract_dir" "$core_extract_dir"
archive_name=tuibox_${os_name}_${arch}.tar.gz
release_archive=$work_dir/$archive_name
release_checksums=$work_dir/checksums.txt

if test "$test_mode" = 1; then
  release_dir=${TUIBOX_RELEASE_DIR:-}
  valid_path "$release_dir" || fail 'test release directory is invalid'
  cp "$release_dir/$archive_name" "$release_archive" || fail 'test release archive is missing'
  cp "$release_dir/checksums.txt" "$release_checksums" || fail 'test release checksums are missing'
else
  if test -z "$release_version"; then
    release_metadata_pages=$work_dir/release-metadata-pages.json
    release_version=$(resolve_release_version "$release_metadata_pages")
  fi
  release_base=https://github.com/$repository/releases/download/$release_version
  download_https "$release_archive" "$release_base/$archive_name" "$max_archive_bytes"
  download_https "$release_checksums" "$release_base/checksums.txt" "$max_checksum_bytes"
fi
valid_payload_file "$release_archive" "$max_archive_bytes" || fail 'release archive is invalid'
valid_payload_file "$release_checksums" "$max_checksum_bytes" || fail 'release checksum file is invalid'
release_digest=$(checksum_for_asset "$release_checksums" "$archive_name")
verify_digest "$release_archive" "$release_digest"
extract_release "$release_archive" "$extract_dir"

core_archive_name=sing-box-$core_version-$os_name-$arch.tar.gz
core_archive=$work_dir/$core_archive_name
if test "$test_mode" = 1; then
  source_core=${TUIBOX_CORE_ARCHIVE:-}
  core_digest=${TUIBOX_CORE_SHA256:-}
  valid_path "$source_core" || fail 'test core archive is invalid'
  cp "$source_core" "$core_archive" || fail 'test core archive is missing'
else
  case $os_name/$arch in
    darwin/amd64) core_digest=5245d645e847f90bb708da74bc020ae078c28489690756419685c04f56b4e3bb ;;
    darwin/arm64) core_digest=73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab ;;
    linux/amd64) core_digest=f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697 ;;
    linux/arm64) core_digest=4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e ;;
    *) fail 'unsupported core platform' ;;
  esac
  download_https "$core_archive" "https://github.com/SagerNet/sing-box/releases/download/v$core_version/$core_archive_name" "$max_archive_bytes"
fi
valid_payload_file "$core_archive" "$max_archive_bytes" || fail 'core archive is invalid'
case $core_digest in
  *[!0-9A-Fa-f]*|'') fail 'core checksum is invalid' ;;
esac
test "${#core_digest}" -eq 64 || fail 'core checksum is invalid'
verify_digest "$core_archive" "$core_digest"
extract_core "$core_archive" "$core_extract_dir"

prepare_service
find_service_manager
preflight_destinations

transaction_active=1
ensure_directory 0755 "$prefix"
ensure_directory 0755 "$prefix/libexec"
ensure_directory 0755 "$libexec_dir"
ensure_directory 0755 "$bin_dir"
ensure_directory 0700 "$state_dir"
ensure_directory 0750 "$run_dir" "$install_gid"
ensure_directory 0755 "$service_dir"
validate_owned_directory "$libexec_dir" "$installed_uid" || fail 'installation directory permissions are invalid'
validate_owned_directory "$bin_dir" "$installed_uid" || fail 'launcher directory permissions are invalid'
validate_owned_directory "$service_dir" "$installed_uid" || fail 'service directory permissions are invalid'
validate_installed_directory "$state_dir" 0700 "$installed_uid" "$root_gid" || fail 'state directory permissions are invalid'
validate_installed_directory "$run_dir" 0750 "$installed_uid" "$install_gid" || fail 'runtime directory permissions are invalid'
for trusted_path in "$prefix" "$prefix/bin" "$prefix/libexec/tuibox" "$state_dir" "$run_dir" "$service_dir"; do
  trusted_parent_chain "$trusted_path" "$trust_uid" "$trust_root" || fail 'installation path became unsafe'
done

stage_regular_file "$extract_dir/tuibox" "$client_path" 0755 "$max_binary_bytes"
stage_regular_file "$extract_dir/tuiboxd" "$daemon_path" 0755 "$max_binary_bytes"
stage_regular_file "$extract_dir/tuibox" "$helper_path" 0755 "$max_binary_bytes"
stage_regular_file "$core_path" "$installed_core_path" 0755 "$max_binary_bytes"
stage_launcher
stage_regular_file "$rendered_service" "$service_path" 0644 "$max_service_bytes"
swap_staged_paths
activate_service
if test "$test_fail_after_service" = 1; then
  fail 'injected post-activation failure'
fi

transaction_committed=1
if ! cleanup_committed_temporary_paths; then
  printf 'TuiBox installed, but obsolete transaction backups could not be removed.\n' >&2
fi
printf 'TuiBox installed. The daemon update takes effect after the service restarts.\n'
