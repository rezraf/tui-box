#!/bin/sh
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

purge_state=0
case $# in
  0) ;;
  1)
    test "$1" = --purge-state || {
      printf 'TuiBox uninstall failed: invalid argument\n' >&2
      exit 1
    }
    purge_state=1
    ;;
  *)
    printf 'TuiBox uninstall failed: invalid arguments\n' >&2
    exit 1
    ;;
esac

test_mode=${TUIBOX_TEST_MODE:-0}
newline='
'

fail() {
  printf 'TuiBox uninstall failed: %s\n' "$1" >&2
  exit 1
}

path_exists() {
  test -e "$1" || test -L "$1"
}

valid_path() {
  case $1 in
    /|'') return 1 ;;
    /*) ;;
    *) return 1 ;;
  esac
  case $1 in
    *[!A-Za-z0-9_./-]*|*//*|*/|*/../*|*/..|*/./*|*/.) return 1 ;;
  esac
  return 0
}

valid_user_path() {
  case $1 in
    /|'') return 1 ;;
    /*) ;;
    *) return 1 ;;
  esac
  case $1 in
    *'|'*|*"$newline"*|*//*|*/|*/../*|*/..|*/./*|*/.) return 1 ;;
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

path_identity() {
  if value=$(stat -f '%d:%i' "$1" 2>/dev/null); then
    printf '%s\n' "$value"
    return
  fi
  stat -c '%d:%i' "$1"
}

trim_spaces() {
  trimmed_value=$1
  while :; do
    case $trimmed_value in
      ' '*) trimmed_value=${trimmed_value# } ;;
      *' ') trimmed_value=${trimmed_value% } ;;
      *) break ;;
    esac
  done
  printf '%s\n' "$trimmed_value"
}

validate_path_acl() {
  test "$os_name" = darwin || return 0
  test "$(uname -s)" = Darwin || return 0
  acl_path=$1
  before_identity=$(path_identity "$acl_path") || return 1
  acl_output=$(/bin/ls -lde -- "$acl_path" 2>/dev/null) || return 1
  test "${#acl_output}" -le 65536 || return 1
  test "$(path_identity "$acl_path")" = "$before_identity" || return 1
  line_number=0
  while IFS= read -r acl_line; do
    line_number=$((line_number + 1))
    test "$line_number" -gt 1 || continue
    acl_entry=$(trim_spaces "$acl_line")
    case $acl_entry in
      *' allow '*) ;;
      *) continue ;;
    esac
    principal=${acl_entry%% allow *}
    case $principal in
      *' '*) principal=${principal#* } ;;
    esac
    test "$principal" = user:root && continue
    permissions=${acl_entry#* allow }
    saved_ifs=$IFS
    IFS=,
    for permission in $permissions; do
      permission=$(trim_spaces "$permission")
      case $permission in
        write|append|delete|delete_child|add_file|add_subdirectory|writeattr|writeextattr|writesecurity|chown)
          IFS=$saved_ifs
          return 1
          ;;
      esac
    done
    IFS=$saved_ifs
  done <<EOF_ACL
$acl_output
EOF_ACL
  return 0
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
  while ! path_exists "$path"; do
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
    secure_mode "$mode" || return 1
    validate_path_acl "$path" || return 1
    test "$path" = "$trusted_root" && return 0
    parent=${path%/*}
    test -n "$parent" || parent=/
    test "$parent" != "$path" || return 1
    path=$parent
  done
}

as_root() {
  if test "$test_mode" = 1 || test "$(id -u)" -eq 0; then
    "$@"
  else
    /usr/bin/sudo -- "$@"
  fi
}

prepare_user_runner() {
  current_uid=$(id -u)
  if test "$current_uid" -eq "$user_uid"; then
    user_runner=self
    return 0
  fi
  if test "$current_uid" -eq 0 && test -x /usr/bin/sudo && test ! -L /usr/bin/sudo; then
    user_runner=sudo
    return 0
  fi
  fail 'user state cannot be purged with the selected UID'
}

as_user() {
  if test "$user_runner" = self; then
    "$@"
  else
    /usr/bin/sudo -u "#$user_uid" -- "$@"
  fi
}

detect_os() {
  if test "$test_mode" = 1; then
    os_name=${TUIBOX_OS:-}
  else
    case $(uname -s) in
      Linux) os_name=linux ;;
      Darwin) os_name=darwin ;;
      *) fail 'unsupported operating system' ;;
    esac
  fi
  case $os_name in
    linux|darwin) ;;
    *) fail 'unsupported operating system' ;;
  esac
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

validate_layout() {
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
    paths_overlap "$first_path" "$second_path" && fail 'managed uninstall paths overlap'
  done
  test "$purge_state" -eq 1 || return 0
  for user_path in "$user_data_dir" "$user_config_dir"; do
    for system_path in "$libexec_dir" "$bin_dir" "$state_dir" "$run_dir" "$service_dir"; do
      paths_overlap "$user_path" "$system_path" && fail 'managed uninstall paths overlap'
    done
  done
  if test "$user_data_dir" != "$user_config_dir"; then
    paths_overlap "$user_data_dir" "$user_config_dir" && fail 'managed uninstall paths overlap'
  fi
  return 0
}

require_home() {
  test "${HOME+x}" = x && test -n "$HOME" || fail 'HOME is required to resolve user paths'
  valid_user_path "$HOME" || fail 'HOME path is invalid'
}

resolve_user_paths() {
  if test "$os_name" = linux; then
    if test "${TUIBOX_USER_DATA_DIR+x}" = x; then
      user_data_dir=$TUIBOX_USER_DATA_DIR
    elif test -n "${XDG_DATA_HOME:-}"; then
      user_data_dir=$XDG_DATA_HOME/tuibox
    else
      require_home
      user_data_dir=$HOME/.local/share/tuibox
    fi
    if test "${TUIBOX_USER_CONFIG_DIR+x}" = x; then
      user_config_dir=$TUIBOX_USER_CONFIG_DIR
    elif test -n "${XDG_CONFIG_HOME:-}"; then
      user_config_dir=$XDG_CONFIG_HOME/tuibox
    else
      require_home
      user_config_dir=$HOME/.config/tuibox
    fi
  else
    if test "${TUIBOX_USER_DATA_DIR+x}" != x || test "${TUIBOX_USER_CONFIG_DIR+x}" != x; then
      require_home
      default_user_dir=$HOME/Library/Application\ Support/tuibox
    fi
    if test "${TUIBOX_USER_DATA_DIR+x}" = x; then
      user_data_dir=$TUIBOX_USER_DATA_DIR
    else
      user_data_dir=$default_user_dir
    fi
    if test "${TUIBOX_USER_CONFIG_DIR+x}" = x; then
      user_config_dir=$TUIBOX_USER_CONFIG_DIR
    else
      user_config_dir=$default_user_dir
    fi
  fi
  valid_user_path "$user_data_dir" || fail 'user data path is invalid'
  valid_user_path "$user_config_dir" || fail 'user config path is invalid'
}

pinned_paths=

record_pin() {
  pin_kind=$1
  pin_value=$2
  pin_path=$3
  pinned_paths="$pinned_paths
$pin_kind|$pin_value|$pin_path"
}

pin_directory_chain() {
  directory_path=$1
  allowed_uid=$2
  trusted_parent_chain "$directory_path" "$allowed_uid" "$trust_root" || return 1
  if path_exists "$directory_path"; then
    record_pin D "$(path_identity "$directory_path")" "$directory_path"
    current_path=$directory_path
  else
    record_pin M - "$directory_path"
    current_path=$directory_path
    while ! path_exists "$current_path"; do
      parent=${current_path%/*}
      test -n "$parent" || parent=/
      test "$parent" != "$current_path" || return 1
      current_path=$parent
    done
  fi
  while :; do
    record_pin D "$(path_identity "$current_path")" "$current_path"
    test "$current_path" = "$trust_root" && return 0
    parent=${current_path%/*}
    test -n "$parent" || parent=/
    test "$parent" != "$current_path" || return 1
    current_path=$parent
  done
}

pin_regular_path() {
  regular_path=$1
  allowed_uid=$2
  if ! path_exists "$regular_path"; then
    record_pin M - "$regular_path"
    return 0
  fi
  test -f "$regular_path" && test ! -L "$regular_path" || return 1
  uid=$(directory_uid "$regular_path") || return 1
  if test "$uid" -ne 0 && test "$uid" -ne "$allowed_uid"; then
    return 1
  fi
  validate_path_acl "$regular_path" || return 1
  record_pin F "$(path_identity "$regular_path")" "$regular_path"
}

pin_user_directory_chain() {
  user_directory=$1
  pin_directory_chain "$user_directory" "$user_uid" || return 1
  path_exists "$user_directory" || return 0
  test "$(directory_uid "$user_directory")" -eq "$user_uid" || return 1
  user_mode=$(directory_mode "$user_directory") || return 1
  owner_digit=$(((user_mode / 100) % 10))
  case $owner_digit in
    3|7) return 0 ;;
    *) return 1 ;;
  esac
}

pin_user_regular_path() {
  regular_path=$1
  if ! path_exists "$regular_path"; then
    record_pin M - "$regular_path"
    return 0
  fi
  test -f "$regular_path" && test ! -L "$regular_path" || return 1
  test "$(directory_uid "$regular_path")" -eq "$user_uid" || return 1
  validate_path_acl "$regular_path" || return 1
  record_pin F "$(path_identity "$regular_path")" "$regular_path"
}

pin_optional_regular_path() {
  regular_path=$1
  allowed_uid=$2
  test -f "$regular_path" && test ! -L "$regular_path" || return 1
  uid=$(directory_uid "$regular_path") || return 1
  if test "$uid" -ne 0 && test "$uid" -ne "$allowed_uid"; then
    return 1
  fi
  validate_path_acl "$regular_path" || return 1
  record_pin O "$(path_identity "$regular_path")" "$regular_path"
}

pin_launcher() {
  if ! path_exists "$launcher_path"; then
    record_pin M - "$launcher_path"
    return 0
  fi
  if test -L "$launcher_path"; then
    test "$(readlink "$launcher_path")" = "$client_path" || return 1
    record_pin L "$client_path" "$launcher_path"
    return 0
  fi
  test -f "$launcher_path" || return 1
  validate_path_acl "$launcher_path" || return 1
  record_pin F "$(path_identity "$launcher_path")" "$launcher_path"
}

pin_socket() {
  if ! path_exists "$socket_path"; then
    record_pin M - "$socket_path"
    return 0
  fi
  test -S "$socket_path" && test ! -L "$socket_path" || return 1
  record_pin S "$(path_identity "$socket_path")" "$socket_path"
}

verify_pinned_paths() {
  while IFS='|' read -r pin_kind pin_value pin_path; do
    test -n "$pin_kind" || continue
    case $pin_kind in
      D)
        test -d "$pin_path" && test ! -L "$pin_path" || return 1
        test "$(path_identity "$pin_path")" = "$pin_value" || return 1
        ;;
      F)
        test -f "$pin_path" && test ! -L "$pin_path" || return 1
        test "$(path_identity "$pin_path")" = "$pin_value" || return 1
        ;;
      L)
        test -L "$pin_path" || return 1
        test "$(readlink "$pin_path")" = "$pin_value" || return 1
        ;;
      M)
        path_exists "$pin_path" && return 1
        ;;
      O)
        if path_exists "$pin_path"; then
          test -f "$pin_path" && test ! -L "$pin_path" || return 1
          test "$(path_identity "$pin_path")" = "$pin_value" || return 1
        fi
        ;;
      S)
        if path_exists "$pin_path"; then
          test -S "$pin_path" && test ! -L "$pin_path" || return 1
          test "$(path_identity "$pin_path")" = "$pin_value" || return 1
        fi
        ;;
      *) return 1 ;;
    esac
  done <<EOF_PINS
$pinned_paths
EOF_PINS
}

known_service_file() {
  if test "$os_name" = linux; then
    grep -F -- "ExecStart=$daemon_path --core $core_path --runtime-dir $state_dir --socket $socket_path" "$service_path" >/dev/null || return 1
    grep -Fx -- 'User=root' "$service_path" >/dev/null || return 1
    return 0
  fi
  grep -F -- '<string>io.github.rezraf.tuiboxd</string>' "$service_path" >/dev/null || return 1
  for value in "$daemon_path" "$core_path" "$state_dir" "$socket_path"; do
    grep -F -- "<string>$value</string>" "$service_path" >/dev/null || return 1
  done
}

preflight_system_entries() {
  for managed_file in "$client_path" "$daemon_path" "$helper_path" "$core_path"; do
    pin_regular_path "$managed_file" "$system_uid" || fail 'managed uninstall file is invalid'
  done
  pin_launcher || fail 'managed launcher path is invalid'
  pin_regular_path "$service_path" "$system_uid" || fail 'managed service path is invalid'
  if path_exists "$service_path"; then
    known_service_file || fail 'managed service file is not a known TuiBox service'
  fi
  pin_socket || fail 'runtime socket path is invalid'
}

hex32='[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
runtime_entries=

list_runtime_entries() {
  path_exists "$state_dir" || return 0
  find -P "$state_dir" ! -path "$state_dir" -prune \
    \( -name "config-$hex32.json" -o -name ".config-$hex32.tmp" \) -print
}

preflight_runtime_entries() {
  runtime_entries=$(list_runtime_entries) || fail 'runtime state paths could not be resolved'
  while IFS= read -r runtime_entry; do
    test -n "$runtime_entry" || continue
    pin_optional_regular_path "$runtime_entry" "$system_uid" || fail 'runtime state entry is invalid'
  done <<EOF_RUNTIME
$runtime_entries
EOF_RUNTIME
}

runtime_entry_was_preflighted() {
  candidate_entry=$1
  while IFS= read -r runtime_entry; do
    test "$runtime_entry" = "$candidate_entry" && return 0
  done <<EOF_RUNTIME
$runtime_entries
EOF_RUNTIME
  return 1
}

verify_runtime_entries() {
  current_entries=$(list_runtime_entries) || return 1
  while IFS= read -r runtime_entry; do
    test -n "$runtime_entry" || continue
    runtime_entry_was_preflighted "$runtime_entry" || return 1
  done <<EOF_RUNTIME
$current_entries
EOF_RUNTIME
}

preflight_user_entries() {
  for user_file in \
    "$user_data_dir/state.json" \
    "$user_data_dir/.state.lock" \
    "$user_config_dir/secrets.json" \
    "$user_config_dir/.secrets.lock"
  do
    valid_user_path "$user_file" || fail 'user state path is invalid'
    pin_user_regular_path "$user_file" || fail 'user state entry is invalid'
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
  test "$(directory_uid "$service_manager")" -eq "$system_uid" || fail 'service manager ownership is invalid'
  secure_mode "$(directory_mode "$service_manager")" || fail 'service manager permissions are invalid'
  service_manager_parent=${service_manager%/*}
  test -n "$service_manager_parent" || service_manager_parent=/
  pin_directory_chain "$service_manager_parent" "$system_uid" || fail 'service manager path is unsafe'
  pin_regular_path "$service_manager" "$system_uid" || fail 'service manager path is unsafe'
}

run_service_manager() {
  as_root "$service_manager" "$@"
}

linux_load_state() {
  if value=$(run_service_manager show --property=LoadState --value tuiboxd.service 2>/dev/null); then
    case $value in
      loaded|not-found) printf '%s\n' "$value" ;;
      *) return 1 ;;
    esac
    return 0
  fi
  return 1
}

linux_active_state() {
  if value=$(run_service_manager show --property=ActiveState --value tuiboxd.service 2>/dev/null); then
    case $value in
      active|activating|deactivating|failed|inactive|reloading) printf '%s\n' "$value" ;;
      *) return 1 ;;
    esac
    return 0
  fi
  return 1
}

stop_linux_service() {
  if run_service_manager disable --now tuiboxd.service >/dev/null 2>&1; then
    :
  else
    load_state=$(linux_load_state) || fail 'systemd service stop failed'
    test "$load_state" = not-found || fail 'systemd service stop failed'
  fi
  load_state=$(linux_load_state) || fail 'systemd service state could not be verified'
  test "$load_state" = not-found && return 0
  active_state=$(linux_active_state) || fail 'systemd service state could not be verified'
  case $active_state in
    inactive|failed) return 0 ;;
    *) fail 'systemd service is still active' ;;
  esac
}

launchd_service_state() {
  if run_service_manager print system/io.github.rezraf.tuiboxd >/dev/null 2>&1; then
    printf 'loaded\n'
    return 0
  else
    result=$?
  fi
  test "$result" -eq 113 || return 1
  printf 'not-found\n'
}

stop_launchd_service() {
  if run_service_manager bootout system/io.github.rezraf.tuiboxd >/dev/null 2>&1; then
    :
  else
    service_state=$(launchd_service_state) || fail 'launchd service stop failed'
    test "$service_state" = not-found || fail 'launchd service stop failed'
  fi
  service_state=$(launchd_service_state) || fail 'launchd service state could not be verified'
  test "$service_state" = not-found || fail 'launchd service is still loaded'
}

stop_service() {
  verify_pinned_paths || fail 'uninstall paths changed before service stop'
  if test "$os_name" = linux; then
    stop_linux_service
  else
    stop_launchd_service
  fi
  verify_pinned_paths || fail 'uninstall paths changed during service stop'
  if test "$purge_state" -eq 1; then
    verify_runtime_entries || fail 'runtime state paths changed during service stop'
  fi
}

remove_regular_file() {
  removal_path=$1
  path_exists "$removal_path" || return 0
  test -f "$removal_path" && test ! -L "$removal_path" || fail 'managed path changed before removal'
  as_root rm -f -- "$removal_path" || fail 'could not remove a managed file'
}

remove_launcher() {
  path_exists "$launcher_path" || return 0
  if test -L "$launcher_path"; then
    test "$(readlink "$launcher_path")" = "$client_path" || fail 'managed launcher changed before removal'
    as_root rm -f -- "$launcher_path" || fail 'could not remove the managed launcher'
  fi
}

remove_socket() {
  path_exists "$socket_path" || return 0
  test -S "$socket_path" && test ! -L "$socket_path" || fail 'runtime socket changed before removal'
  as_root rm -f -- "$socket_path" || fail 'could not remove the runtime socket'
}

remove_empty_directory() {
  removal_directory=$1
  path_exists "$removal_directory" || return 0
  test -d "$removal_directory" && test ! -L "$removal_directory" || fail 'managed directory changed before removal'
  as_root rmdir "$removal_directory" >/dev/null 2>&1 || true
}

remove_runtime_entries() {
  while IFS= read -r runtime_entry; do
    test -n "$runtime_entry" || continue
    path_exists "$runtime_entry" || continue
    test -f "$runtime_entry" && test ! -L "$runtime_entry" || fail 'runtime state entry changed before removal'
    as_root rm -f -- "$runtime_entry" || fail 'could not remove a runtime state entry'
  done <<EOF_RUNTIME
$runtime_entries
EOF_RUNTIME
}

remove_user_regular_file() {
  removal_path=$1
  path_exists "$removal_path" || return 0
  test -f "$removal_path" && test ! -L "$removal_path" || fail 'user state path changed before removal'
  as_user rm -f -- "$removal_path" || fail 'could not remove a user state file'
}

remove_user_entries() {
  for user_file in \
    "$user_data_dir/state.json" \
    "$user_data_dir/.state.lock" \
    "$user_config_dir/secrets.json" \
    "$user_config_dir/.secrets.lock"
  do
    remove_user_regular_file "$user_file"
  done
}

remove_user_empty_directory() {
  removal_directory=$1
  path_exists "$removal_directory" || return 0
  test -d "$removal_directory" && test ! -L "$removal_directory" || fail 'user state directory changed before removal'
  as_user rmdir "$removal_directory" >/dev/null 2>&1 || true
}

detect_os
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
for configured_path in "$prefix" "$etc_dir" "$state_dir" "$run_dir" "$systemd_dir" "$launchd_dir"; do
  valid_path "$configured_path" || fail 'configured path is invalid'
done

if test "$test_mode" = 1; then
  trust_root=${TUIBOX_TEST_TRUST_ROOT:-}
  valid_path "$trust_root" || fail 'test trust root is invalid'
  system_uid=$(id -u)
else
  trust_root=/
  system_uid=0
fi
valid_identity "$system_uid" || fail 'system UID is invalid'

user_uid=${SUDO_UID:-$(id -u)}
valid_identity "$user_uid" || fail 'user UID is invalid'
if test "$purge_state" -eq 1; then
  resolve_user_paths
  prepare_user_runner
fi

libexec_dir=$prefix/libexec/tuibox
bin_dir=$prefix/bin
client_path=$libexec_dir/tuibox
daemon_path=$libexec_dir/tuiboxd
helper_path=$libexec_dir/tuibox-update-helper
core_path=$libexec_dir/sing-box
launcher_path=$bin_dir/tuibox
socket_path=$run_dir/tuiboxd.sock
if test "$os_name" = linux; then
  service_dir=$systemd_dir
  service_path=$service_dir/tuiboxd.service
else
  service_dir=$launchd_dir
  service_path=$service_dir/io.github.rezraf.tuiboxd.plist
fi
for managed_path in \
  "$prefix/libexec" \
  "$libexec_dir" \
  "$bin_dir" \
  "$client_path" \
  "$daemon_path" \
  "$helper_path" \
  "$core_path" \
  "$launcher_path" \
  "$socket_path" \
  "$service_path"
do
  valid_path "$managed_path" || fail 'managed uninstall path is invalid'
done
validate_layout

for system_directory in \
  "$prefix" \
  "$prefix/libexec" \
  "$libexec_dir" \
  "$bin_dir" \
  "$etc_dir" \
  "$state_dir" \
  "$run_dir" \
  "$service_dir"
do
  pin_directory_chain "$system_directory" "$system_uid" || fail 'uninstall path has an unsafe ancestor'
done
if test "$purge_state" -eq 1; then
  pin_user_directory_chain "$user_data_dir" || fail 'user data path has an unsafe ancestor'
  pin_user_directory_chain "$user_config_dir" || fail 'user config path has an unsafe ancestor'
fi

preflight_system_entries
if test "$purge_state" -eq 1; then
  preflight_runtime_entries
  preflight_user_entries
fi
find_service_manager
stop_service

remove_regular_file "$service_path"
remove_launcher
for managed_file in "$client_path" "$daemon_path" "$helper_path" "$core_path"; do
  remove_regular_file "$managed_file"
done
remove_socket
remove_empty_directory "$libexec_dir"
remove_empty_directory "$run_dir"

if test "$purge_state" -eq 1; then
  remove_runtime_entries
  remove_user_entries
  remove_empty_directory "$state_dir"
  remove_user_empty_directory "$user_data_dir"
  if test "$user_config_dir" != "$user_data_dir"; then
    remove_user_empty_directory "$user_config_dir"
  fi
fi

if test "$os_name" = linux; then
  run_service_manager daemon-reload >/dev/null 2>&1 || fail 'systemd daemon reload failed'
fi

if test "$purge_state" -eq 1; then
  state_result=removed
else
  state_result=preserved
fi
printf 'TuiBox uninstalled. User state was %s.\n' "$state_result"
