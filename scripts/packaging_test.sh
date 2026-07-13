#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
root_scope_dir=$(mktemp -d "$repo_dir/.packaging-root.XXXXXX")
trap 'rm -rf "$work_dir" "$root_scope_dir"' EXIT HUP INT TERM

grep -F -- '--max-filesize "$maximum_bytes"' "$repo_dir/install.sh" >/dev/null || {
  printf 'installer downloads are not size bounded\n' >&2
  exit 1
}
for contract in \
  'linux_state_default=/var/lib/tuibox' \
  'linux_run_default=/run/tuibox' \
  'darwin_state_default=/private/var/db/tuibox' \
  'darwin_run_default=/private/var/run/tuibox'
do
  grep -F -- "$contract" "$repo_dir/install.sh" >/dev/null || {
    printf 'installer canonical default missing: %s\n' "$contract" >&2
    exit 1
  }
  grep -F -- "$contract" "$repo_dir/uninstall.sh" >/dev/null || {
    printf 'uninstaller canonical default missing: %s\n' "$contract" >&2
    exit 1
  }
done

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

file_mode() {
  if value=$(stat -f '%OLp' "$1" 2>/dev/null); then
    printf '%s\n' "$value"
    return
  fi
  stat -c '%a' "$1"
}

make_fixtures() {
  fixture_dir=$1
  fixture_label=${2:-fixture}
  mkdir -p "$fixture_dir/release/source"
  printf 'client-%s\n' "$fixture_label" >"$fixture_dir/release/source/tuibox"
  printf 'daemon-%s\n' "$fixture_label" >"$fixture_dir/release/source/tuiboxd"
  chmod 755 "$fixture_dir/release/source/tuibox" "$fixture_dir/release/source/tuiboxd"

  : >"$fixture_dir/release/checksums.txt"
  for fixture_os in linux darwin; do
    archive_name=tuibox_${fixture_os}_amd64.tar.gz
    (cd "$fixture_dir/release/source" && tar -czf "../$archive_name" tuibox tuiboxd)
    release_digest=$(sha256_file "$fixture_dir/release/$archive_name")
    printf '%s  %s\n' "$release_digest" "$archive_name" >>"$fixture_dir/release/checksums.txt"

    core_directory=sing-box-1.13.14-${fixture_os}-amd64
    mkdir -p "$fixture_dir/core/$core_directory"
    printf 'core-%s-%s\n' "$fixture_label" "$fixture_os" >"$fixture_dir/core/$core_directory/sing-box"
    chmod 755 "$fixture_dir/core/$core_directory/sing-box"
    (cd "$fixture_dir/core" && tar -czf "$core_directory.tar.gz" "$core_directory")
  done

  printf '%s\n' \
    '#!/bin/sh' \
    'if test -n "${TUIBOX_TEST_SERVICE_LOG:-}"; then' \
    '  printf '\''%s\n'\'' "$*" >>"$TUIBOX_TEST_SERVICE_LOG"' \
    'fi' \
    'if test -n "${TUIBOX_TEST_REQUIRED_BACKUPS:-}" && { test -z "${TUIBOX_TEST_BACKUP_CHECK_STATE:-}" || test ! -e "$TUIBOX_TEST_BACKUP_CHECK_STATE"; }; then' \
    '  for target in $TUIBOX_TEST_REQUIRED_BACKUPS; do' \
    '    directory=${target%/*}' \
    '    base=${target##*/}' \
    '    backup_found=0' \
    '    for candidate in "$directory/.tuibox-backup.$base."*; do' \
    '      if test -e "$candidate" || test -L "$candidate"; then' \
    '        backup_found=1' \
    '        break' \
    '      fi' \
    '    done' \
    '    test "$backup_found" = 1 || exit 24' \
    '  done' \
    '  if test -n "${TUIBOX_TEST_BACKUP_CHECK_STATE:-}"; then' \
    '    : >"$TUIBOX_TEST_BACKUP_CHECK_STATE"' \
    '  fi' \
    'fi' \
    'case $* in' \
    '  '\''disable --now tuiboxd.service'\''|'\''bootout system/io.github.rezraf.tuiboxd'\'')' \
    '    if test -n "${TUIBOX_TEST_UNINSTALL_REPLACE_PATH:-}" && test ! -e "$TUIBOX_TEST_UNINSTALL_REPLACE_PATH.before" && test ! -L "$TUIBOX_TEST_UNINSTALL_REPLACE_PATH.before"; then' \
    '      mv "$TUIBOX_TEST_UNINSTALL_REPLACE_PATH" "$TUIBOX_TEST_UNINSTALL_REPLACE_PATH.before" || exit 25' \
    '      ln -s "$TUIBOX_TEST_UNINSTALL_REPLACE_WITH" "$TUIBOX_TEST_UNINSTALL_REPLACE_PATH" || exit 25' \
    '    fi' \
    '    ;;' \
    'esac' \
    'uninstall_mode=${TUIBOX_TEST_UNINSTALL_SERVICE_MODE:-inactive}' \
    'case $* in' \
    '  '\''disable --now tuiboxd.service'\'')' \
    '    case $uninstall_mode in not-found|stop-failure) exit 23 ;; esac' \
    '    ;;' \
    '  '\''show --property=LoadState --value tuiboxd.service'\'')' \
    '    case $uninstall_mode in not-found) printf '\''not-found\n'\'' ;; *) printf '\''loaded\n'\'' ;; esac' \
    '    exit 0' \
    '    ;;' \
    '  '\''show --property=ActiveState --value tuiboxd.service'\'')' \
    '    case $uninstall_mode in still-active) printf '\''active\n'\'' ;; *) printf '\''inactive\n'\'' ;; esac' \
    '    exit 0' \
    '    ;;' \
    '  '\''bootout system/io.github.rezraf.tuiboxd'\'')' \
    '    case $uninstall_mode in launchd-not-found|launchd-stop-failure) exit 23 ;; esac' \
    '    ;;' \
    '  '\''print system/io.github.rezraf.tuiboxd'\'')' \
    '    case $uninstall_mode in launchd-stop-failure|launchd-still-active) exit 0 ;; *) exit 113 ;; esac' \
    '    ;;' \
    'esac' \
    'if test -n "${TUIBOX_TEST_SERVICE_FAIL_MATCH:-}" && test "$*" = "$TUIBOX_TEST_SERVICE_FAIL_MATCH"; then' \
    '  if test -z "${TUIBOX_TEST_SERVICE_FAIL_STATE:-}" || test ! -e "$TUIBOX_TEST_SERVICE_FAIL_STATE"; then' \
    '    if test -n "${TUIBOX_TEST_SERVICE_FAIL_STATE:-}"; then' \
    '      : >"$TUIBOX_TEST_SERVICE_FAIL_STATE"' \
    '    fi' \
    '    exit 23' \
    '  fi' \
    'fi' \
    'exit 0' >"$fixture_dir/service-manager"
  chmod 755 "$fixture_dir/service-manager"
}

run_install_platform() {
  root=$1
  fixture=$2
  fixture_os=$3
  test_trust_root=${4:-${root%/*}}
  core_archive=$fixture/core/sing-box-1.13.14-${fixture_os}-amd64.tar.gz
  core_digest=$(sha256_file "$core_archive")
  env \
    TUIBOX_TEST_MODE=1 \
    TUIBOX_TEST_TRUST_ROOT="$test_trust_root" \
    TUIBOX_OS="$fixture_os" \
    TUIBOX_ARCH=amd64 \
    TUIBOX_PREFIX="${TUIBOX_TEST_PREFIX:-$root/prefix}" \
    TUIBOX_ETC_DIR="${TUIBOX_TEST_ETC_DIR:-$root/etc}" \
    TUIBOX_STATE_DIR="${TUIBOX_TEST_STATE_DIR:-$root/state}" \
    TUIBOX_RUN_DIR="${TUIBOX_TEST_RUN_DIR:-$root/run}" \
    TUIBOX_SYSTEMD_DIR="${TUIBOX_TEST_SYSTEMD_DIR:-$root/systemd}" \
    TUIBOX_LAUNCHD_DIR="${TUIBOX_TEST_LAUNCHD_DIR:-$root/launchd}" \
    TUIBOX_RELEASE_DIR="$fixture/release" \
    TUIBOX_CORE_ARCHIVE="$core_archive" \
    TUIBOX_CORE_SHA256="$core_digest" \
    TUIBOX_UID="$(id -u)" \
    TUIBOX_GID="$(id -g)" \
    TUIBOX_TEST_SERVICE_MANAGER="${TUIBOX_TEST_SERVICE_MANAGER:-$fixture/service-manager}" \
    TUIBOX_TEST_SERVICE_LOG="${TUIBOX_TEST_SERVICE_LOG:-$fixture/service-manager.log}" \
    TUIBOX_TEST_SERVICE_FAIL_MATCH="${TUIBOX_TEST_SERVICE_FAIL_MATCH:-}" \
    TUIBOX_TEST_SERVICE_FAIL_STATE="${TUIBOX_TEST_SERVICE_FAIL_STATE:-}" \
    TUIBOX_TEST_SERVICE_TEMPLATE="${TUIBOX_TEST_SERVICE_TEMPLATE:-}" \
    TUIBOX_TEST_REQUIRED_BACKUPS="${TUIBOX_TEST_REQUIRED_BACKUPS:-}" \
    TUIBOX_TEST_BACKUP_CHECK_STATE="${TUIBOX_TEST_BACKUP_CHECK_STATE:-}" \
    TUIBOX_TEST_FAIL_AFTER_SERVICE="${TUIBOX_TEST_FAIL_AFTER_SERVICE:-0}" \
    sh "$repo_dir/install.sh"
}

run_install() {
  run_install_platform "$1" "$2" linux "${3:-${2%/*}}"
}

run_uninstall_platform() {
  uninstall_root=$1
  uninstall_fixture=$2
  uninstall_os=$3
  shift 3
  env \
    TUIBOX_TEST_MODE=1 \
    TUIBOX_TEST_TRUST_ROOT="${TUIBOX_TEST_TRUST_ROOT-${uninstall_fixture%/*}}" \
    TUIBOX_OS="$uninstall_os" \
    TUIBOX_PREFIX="${TUIBOX_TEST_PREFIX-$uninstall_root/prefix}" \
    TUIBOX_ETC_DIR="${TUIBOX_TEST_ETC_DIR-$uninstall_root/etc}" \
    TUIBOX_STATE_DIR="${TUIBOX_TEST_STATE_DIR-$uninstall_root/state}" \
    TUIBOX_RUN_DIR="${TUIBOX_TEST_RUN_DIR-$uninstall_root/run}" \
    TUIBOX_SYSTEMD_DIR="${TUIBOX_TEST_SYSTEMD_DIR-$uninstall_root/systemd}" \
    TUIBOX_LAUNCHD_DIR="${TUIBOX_TEST_LAUNCHD_DIR-$uninstall_root/launchd}" \
    TUIBOX_USER_DATA_DIR="${TUIBOX_TEST_USER_DATA_DIR-$uninstall_root/user-data}" \
    TUIBOX_USER_CONFIG_DIR="${TUIBOX_TEST_USER_CONFIG_DIR-$uninstall_root/user-config}" \
    TUIBOX_TEST_SERVICE_MANAGER="${TUIBOX_TEST_SERVICE_MANAGER-$uninstall_fixture/service-manager}" \
    TUIBOX_TEST_SERVICE_LOG="${TUIBOX_TEST_SERVICE_LOG-$uninstall_root/uninstall-service.log}" \
    TUIBOX_TEST_UNINSTALL_SERVICE_MODE="${TUIBOX_TEST_UNINSTALL_SERVICE_MODE-inactive}" \
    TUIBOX_TEST_UNINSTALL_REPLACE_PATH="${TUIBOX_TEST_UNINSTALL_REPLACE_PATH-}" \
    TUIBOX_TEST_UNINSTALL_REPLACE_WITH="${TUIBOX_TEST_UNINSTALL_REPLACE_WITH-}" \
    TUIBOX_TEST_PATH_MARKER="${TUIBOX_TEST_PATH_MARKER-}" \
    PATH="${TUIBOX_TEST_PATH-$PATH}" \
    HOME="${TUIBOX_TEST_HOME-$uninstall_root/home}" \
    SUDO_UID="$(id -u)" \
    sh "$repo_dir/uninstall.sh" "$@"
}

run_uninstall() {
  uninstall_root=$1
  uninstall_fixture=$2
  shift 2
  run_uninstall_platform "$uninstall_root" "$uninstall_fixture" linux "$@"
}

assert_install_intact() {
  intact_root=$1
  intact_os=${2:-linux}
  for managed_file in \
    "$intact_root/prefix/libexec/tuibox/tuibox" \
    "$intact_root/prefix/libexec/tuibox/tuiboxd" \
    "$intact_root/prefix/libexec/tuibox/tuibox-update-helper" \
    "$intact_root/prefix/libexec/tuibox/sing-box"
  do
    test -f "$managed_file" || {
      printf 'managed install changed before safe service stop: %s\n' "$managed_file" >&2
      return 1
    }
  done
  test -L "$intact_root/prefix/bin/tuibox" || {
    printf 'managed launcher changed before safe service stop\n' >&2
    return 1
  }
  if test "$intact_os" = linux; then
    service_file=$intact_root/systemd/tuiboxd.service
  else
    service_file=$intact_root/launchd/io.github.rezraf.tuiboxd.plist
  fi
  test -f "$service_file" || {
    printf 'managed service changed before safe service stop: %s\n' "$service_file" >&2
    return 1
  }
}

assert_service_stop_not_attempted() {
  stop_log=$1
  test ! -e "$stop_log" && return 0
  if grep -Eq '^(disable --now tuiboxd\.service|bootout system/io\.github\.rezraf\.tuiboxd)$' "$stop_log"; then
    printf 'service stop was attempted before uninstall preflight completed\n' >&2
    return 1
  fi
}

prepare_user_state() {
  user_root=$1
  mkdir -p "$user_root/user-data" "$user_root/user-config"
  printf 'state\n' >"$user_root/user-data/state.json"
  printf 'lock\n' >"$user_root/user-data/.state.lock"
  printf 'secret\n' >"$user_root/user-config/secrets.json"
  printf 'lock\n' >"$user_root/user-config/.secrets.lock"
}

assert_path_absent() {
  if test -e "$1" || test -L "$1"; then
    printf 'unexpected managed path after failed install: %s\n' "$1" >&2
    return 1
  fi
}

assert_no_installed_files() {
  install_test_root=$1
  for candidate in \
    "$install_test_root/prefix/libexec/tuibox/tuibox" \
    "$install_test_root/prefix/libexec/tuibox/tuiboxd" \
    "$install_test_root/prefix/libexec/tuibox/tuibox-update-helper" \
    "$install_test_root/prefix/libexec/tuibox/sing-box" \
    "$install_test_root/prefix/bin/tuibox" \
    "$install_test_root/systemd/tuiboxd.service" \
    "$install_test_root/launchd/io.github.rezraf.tuiboxd.plist"
  do
    assert_path_absent "$candidate"
  done
}

assert_no_transaction_artifacts() {
  install_test_root=$1
  test -d "$install_test_root" || return 0
  artifacts=$(find "$install_test_root" \( -name '.tuibox-stage.*' -o -name '.tuibox-backup.*' \) -print)
  if test -n "$artifacts"; then
    printf 'installer transaction artifacts remain:\n%s\n' "$artifacts" >&2
    return 1
  fi
}

assert_fresh_install_rolled_back() {
  install_test_root=$1
  assert_no_installed_files "$install_test_root"
  for candidate in \
    "$install_test_root/prefix/libexec/tuibox" \
    "$install_test_root/prefix/libexec" \
    "$install_test_root/prefix/bin" \
    "$install_test_root/prefix" \
    "$install_test_root/state" \
    "$install_test_root/run" \
    "$install_test_root/systemd" \
    "$install_test_root/launchd"
  do
    if test -d "$candidate"; then
      printf 'new managed directory remains after failed install: %s\n' "$candidate" >&2
      return 1
    fi
  done
  assert_no_transaction_artifacts "$install_test_root"
}

snapshot_install() {
  snapshot_root=$1
  snapshot_dir=$2
  mkdir -p "$snapshot_dir"
  cp -p "$snapshot_root/prefix/libexec/tuibox/tuibox" "$snapshot_dir/client"
  cp -p "$snapshot_root/prefix/libexec/tuibox/tuiboxd" "$snapshot_dir/daemon"
  cp -p "$snapshot_root/prefix/libexec/tuibox/tuibox-update-helper" "$snapshot_dir/helper"
  cp -p "$snapshot_root/prefix/libexec/tuibox/sing-box" "$snapshot_dir/core"
  cp -p "$snapshot_root/systemd/tuiboxd.service" "$snapshot_dir/service"
  readlink "$snapshot_root/prefix/bin/tuibox" >"$snapshot_dir/launcher-target"
}

assert_snapshot_file() {
  installed_path=$1
  snapshot_path=$2
  cmp "$installed_path" "$snapshot_path" || {
    printf 'installed file changed after rollback: %s\n' "$installed_path" >&2
    return 1
  }
  test "$(file_mode "$installed_path")" = "$(file_mode "$snapshot_path")" || {
    printf 'installed file mode changed after rollback: %s\n' "$installed_path" >&2
    return 1
  }
}

assert_install_matches_snapshot() {
  snapshot_root=$1
  snapshot_dir=$2
  assert_snapshot_file "$snapshot_root/prefix/libexec/tuibox/tuibox" "$snapshot_dir/client"
  assert_snapshot_file "$snapshot_root/prefix/libexec/tuibox/tuiboxd" "$snapshot_dir/daemon"
  assert_snapshot_file "$snapshot_root/prefix/libexec/tuibox/tuibox-update-helper" "$snapshot_dir/helper"
  assert_snapshot_file "$snapshot_root/prefix/libexec/tuibox/sing-box" "$snapshot_dir/core"
  assert_snapshot_file "$snapshot_root/systemd/tuiboxd.service" "$snapshot_dir/service"
  expected_launcher=$(readlink "$snapshot_root/prefix/bin/tuibox")
  saved_launcher=$(readlink "$snapshot_dir/launcher-target" 2>/dev/null || true)
  if test -z "$saved_launcher"; then
    saved_launcher=$(tr -d '\n' <"$snapshot_dir/launcher-target")
  fi
  test "$expected_launcher" = "$saved_launcher" || {
    printf 'launcher target changed after rollback: %s\n' "$snapshot_root/prefix/bin/tuibox" >&2
    return 1
  }
  assert_no_transaction_artifacts "$snapshot_root"
}

test_invalid_service_template_preflight() {
  case_dir=$1
  case_fixture=$2
  mkdir -p "$case_dir"
  invalid_template=$case_dir/invalid.service
  printf '[Unit]\nDescription=not a TuiBox service\n' >"$invalid_template"
  if (TUIBOX_TEST_SERVICE_TEMPLATE="$invalid_template" run_install "$case_dir/install" "$case_fixture" >/dev/null 2>&1); then
    printf 'invalid service template was accepted\n' >&2
    return 1
  fi
  assert_fresh_install_rolled_back "$case_dir/install"
}

test_missing_service_manager_preflight() {
  case_dir=$1
  case_fixture=$2
  mkdir -p "$case_dir"
  if (TUIBOX_TEST_SERVICE_MANAGER="$case_dir/missing-service-manager" run_install "$case_dir/install" "$case_fixture" >/dev/null 2>&1); then
    printf 'missing service manager was accepted\n' >&2
    return 1
  fi
  assert_fresh_install_rolled_back "$case_dir/install"
}

test_destination_type_preflight() {
  case_dir=$1
  case_fixture=$2
  install_test_root=$case_dir/install
  client_collision=$install_test_root/prefix/libexec/tuibox/tuibox
  mkdir -p "$client_collision"
  if run_install "$install_test_root" "$case_fixture" >/dev/null 2>&1; then
    printf 'directory at managed file destination was accepted\n' >&2
    return 1
  fi
  test -d "$client_collision" || {
    printf 'managed destination collision was replaced\n' >&2
    return 1
  }
  collision_contents=$(find "$client_collision" -mindepth 1 -print)
  test -z "$collision_contents" || {
    printf 'managed destination collision was mutated before rejection\n' >&2
    return 1
  }
  for candidate in \
    "$install_test_root/prefix/libexec/tuibox/tuiboxd" \
    "$install_test_root/prefix/libexec/tuibox/tuibox-update-helper" \
    "$install_test_root/prefix/libexec/tuibox/sing-box" \
    "$install_test_root/prefix/bin/tuibox" \
    "$install_test_root/state" \
    "$install_test_root/run" \
    "$install_test_root/systemd/tuiboxd.service"
  do
    assert_path_absent "$candidate"
  done
  assert_no_transaction_artifacts "$install_test_root"
}

test_overlapping_destination_preflight() {
  case_dir=$1
  case_fixture=$2
  mkdir -p "$case_dir/install"
  if (TUIBOX_TEST_STATE_DIR="$case_dir/install/prefix/bin" run_install "$case_dir/install" "$case_fixture" >/dev/null 2>&1); then
    printf 'overlapping managed destinations were accepted\n' >&2
    return 1
  fi
  assert_fresh_install_rolled_back "$case_dir/install"
}

test_unknown_managed_collisions() {
  case_dir=$1
  case_fixture=$2
  for collision_kind in helper launcher service; do
    install_test_root=$case_dir/$collision_kind
    sentinel=$case_dir/$collision_kind.before
    case $collision_kind in
      helper)
        collision_path=$install_test_root/prefix/libexec/tuibox/tuibox-update-helper
        mkdir -p "${collision_path%/*}"
        ;;
      launcher)
        collision_path=$install_test_root/prefix/bin/tuibox
        mkdir -p "${collision_path%/*}"
        ;;
      service)
        collision_path=$install_test_root/systemd/tuiboxd.service
        mkdir -p "${collision_path%/*}"
        ;;
    esac
    printf 'unknown-%s\n' "$collision_kind" >"$collision_path"
    cp -p "$collision_path" "$sentinel"
    if run_install "$install_test_root" "$case_fixture" >/dev/null 2>&1; then
      printf 'unknown pre-existing %s path was accepted\n' "$collision_kind" >&2
      return 1
    fi
    cmp "$collision_path" "$sentinel" || {
      printf 'unknown pre-existing %s path was modified\n' "$collision_kind" >&2
      return 1
    }
    for candidate in \
      "$install_test_root/prefix/libexec/tuibox/tuibox" \
      "$install_test_root/prefix/libexec/tuibox/tuiboxd" \
      "$install_test_root/prefix/libexec/tuibox/sing-box"
    do
      assert_path_absent "$candidate"
    done
    assert_no_transaction_artifacts "$install_test_root"
  done
}

linux_managed_paths() {
  install_test_root=$1
  printf '%s\n' \
    "$install_test_root/prefix/libexec/tuibox/tuibox" \
    "$install_test_root/prefix/libexec/tuibox/tuiboxd" \
    "$install_test_root/prefix/libexec/tuibox/tuibox-update-helper" \
    "$install_test_root/prefix/libexec/tuibox/sing-box" \
    "$install_test_root/prefix/bin/tuibox" \
    "$install_test_root/systemd/tuiboxd.service"
}

assert_existing_service_reactivated() {
  service_log=$1
  reload_count=$(grep -Fxc 'daemon-reload' "$service_log" || true)
  enable_count=$(grep -Fxc 'enable --now tuiboxd.service' "$service_log" || true)
  if test "$reload_count" -lt 2 || test "$enable_count" -lt 2; then
    printf 'existing service was not reloaded and reactivated after rollback\n' >&2
    return 1
  fi
}

test_fresh_activation_failure_rolls_back() {
  case_dir=$1
  case_fixture=$2
  mkdir -p "$case_dir"
  service_log=$case_dir/service.log
  fail_state=$case_dir/service-failed
  if (
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
      TUIBOX_TEST_SERVICE_FAIL_MATCH='enable --now tuiboxd.service' \
      TUIBOX_TEST_SERVICE_FAIL_STATE="$fail_state" \
      run_install "$case_dir/install" "$case_fixture" >/dev/null 2>&1
  )
  then
    printf 'service activation failure was accepted for a fresh install\n' >&2
    return 1
  fi
  assert_fresh_install_rolled_back "$case_dir/install"
  grep -Fx 'disable --now tuiboxd.service' "$service_log" >/dev/null || {
    printf 'fresh service activation was not undone after rollback\n' >&2
    return 1
  }
}

test_existing_activation_failure_restores_install() {
  case_dir=$1
  mkdir -p "$case_dir"
  make_fixtures "$case_dir/old-fixture" old
  make_fixtures "$case_dir/new-fixture" new
  install_test_root=$case_dir/install
  run_install "$install_test_root" "$case_dir/old-fixture" >/dev/null
  snapshot_install "$install_test_root" "$case_dir/snapshot"
  service_log=$case_dir/service.log
  : >"$service_log"
  fail_state=$case_dir/service-failed
  backup_state=$case_dir/backups-checked
  required_backups=$(linux_managed_paths "$install_test_root" | tr '\n' ' ')
  if (
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
      TUIBOX_TEST_SERVICE_FAIL_MATCH='enable --now tuiboxd.service' \
      TUIBOX_TEST_SERVICE_FAIL_STATE="$fail_state" \
      TUIBOX_TEST_REQUIRED_BACKUPS="$required_backups" \
      TUIBOX_TEST_BACKUP_CHECK_STATE="$backup_state" \
      run_install "$install_test_root" "$case_dir/new-fixture" >/dev/null 2>&1
  )
  then
    printf 'service activation failure was accepted for an existing install\n' >&2
    return 1
  fi
  test -f "$backup_state" || {
    printf 'managed backups were not staged beside destination files\n' >&2
    return 1
  }
  assert_install_matches_snapshot "$install_test_root" "$case_dir/snapshot"
  assert_existing_service_reactivated "$service_log"
}

test_post_activation_failure_restores_install() {
  case_dir=$1
  mkdir -p "$case_dir"
  make_fixtures "$case_dir/old-fixture" old
  make_fixtures "$case_dir/new-fixture" new
  install_test_root=$case_dir/install
  run_install "$install_test_root" "$case_dir/old-fixture" >/dev/null
  snapshot_install "$install_test_root" "$case_dir/snapshot"
  service_log=$case_dir/service.log
  : >"$service_log"
  backup_state=$case_dir/backups-checked
  required_backups=$(linux_managed_paths "$install_test_root" | tr '\n' ' ')
  if (
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
      TUIBOX_TEST_REQUIRED_BACKUPS="$required_backups" \
      TUIBOX_TEST_BACKUP_CHECK_STATE="$backup_state" \
      TUIBOX_TEST_FAIL_AFTER_SERVICE=1 \
      run_install "$install_test_root" "$case_dir/new-fixture" >/dev/null 2>&1
  )
  then
    printf 'post-activation failure was accepted\n' >&2
    return 1
  fi
  test -f "$backup_state" || {
    printf 'managed backups were not present during service activation\n' >&2
    return 1
  }
  assert_install_matches_snapshot "$install_test_root" "$case_dir/snapshot"
  assert_existing_service_reactivated "$service_log"
}

test_uninstall_missing_home_preflight() {
  case_dir=$1
  case_fixture=$2
  install_test_root=$case_dir/install
  service_log=$case_dir/service.log
  mkdir -p "$case_dir"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  : >"$service_log"
  if (
    unset HOME XDG_DATA_HOME XDG_CONFIG_HOME TUIBOX_USER_DATA_DIR TUIBOX_USER_CONFIG_DIR
    env \
      TUIBOX_TEST_MODE=1 \
      TUIBOX_TEST_TRUST_ROOT="${case_fixture%/*}" \
      TUIBOX_OS=linux \
      TUIBOX_PREFIX="$install_test_root/prefix" \
      TUIBOX_ETC_DIR="$install_test_root/etc" \
      TUIBOX_STATE_DIR="$install_test_root/state" \
      TUIBOX_RUN_DIR="$install_test_root/run" \
      TUIBOX_SYSTEMD_DIR="$install_test_root/systemd" \
      TUIBOX_LAUNCHD_DIR="$install_test_root/launchd" \
      TUIBOX_TEST_SERVICE_MANAGER="$case_fixture/service-manager" \
      TUIBOX_TEST_SERVICE_LOG="$service_log" \
      SUDO_UID="$(id -u)" \
      sh "$repo_dir/uninstall.sh" --purge-state >/dev/null 2>&1
  )
  then
    printf 'purge without HOME was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
}

test_uninstall_path_preflight() {
  case_dir=$1
  case_fixture=$2
  token=0123456789abcdef0123456789abcdef

  install_test_root=$case_dir/state-symlink/install
  mkdir -p "$case_dir/state-symlink/outside-state"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  rmdir "$install_test_root/state"
  printf 'outside-config\n' >"$case_dir/state-symlink/outside-state/config-$token.json"
  ln -s "$case_dir/state-symlink/outside-state" "$install_test_root/state"
  prepare_user_state "$install_test_root"
  service_log=$case_dir/state-symlink/service.log
  : >"$service_log"
  if TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1; then
    printf 'symlinked state directory was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
  test -f "$case_dir/state-symlink/outside-state/config-$token.json" || {
    printf 'symlinked state directory target was mutated\n' >&2
    return 1
  }

  install_test_root=$case_dir/user-data-symlink/install
  mkdir -p "$case_dir/user-data-symlink/outside-data" "$install_test_root/user-config"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  printf 'outside-state\n' >"$case_dir/user-data-symlink/outside-data/state.json"
  printf 'secret\n' >"$install_test_root/user-config/secrets.json"
  ln -s "$case_dir/user-data-symlink/outside-data" "$install_test_root/user-data"
  service_log=$case_dir/user-data-symlink/service.log
  : >"$service_log"
  if TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1; then
    printf 'symlinked user data directory was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
  test -f "$case_dir/user-data-symlink/outside-data/state.json" || {
    printf 'symlinked user data target was mutated\n' >&2
    return 1
  }

  install_test_root=$case_dir/user-config-symlink/install
  mkdir -p "$case_dir/user-config-symlink/outside-config" "$install_test_root/user-data"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  printf 'state\n' >"$install_test_root/user-data/state.json"
  printf 'outside-secret\n' >"$case_dir/user-config-symlink/outside-config/secrets.json"
  ln -s "$case_dir/user-config-symlink/outside-config" "$install_test_root/user-config"
  service_log=$case_dir/user-config-symlink/service.log
  : >"$service_log"
  if TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1; then
    printf 'symlinked user config directory was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
  test -f "$case_dir/user-config-symlink/outside-config/secrets.json" || {
    printf 'symlinked user config target was mutated\n' >&2
    return 1
  }

  install_test_root=$case_dir/unsafe-user-ancestor/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  mkdir -p "$case_dir/unsafe-user-ancestor/writable/user-data" "$install_test_root/user-config"
  chmod 0777 "$case_dir/unsafe-user-ancestor/writable"
  printf 'state\n' >"$case_dir/unsafe-user-ancestor/writable/user-data/state.json"
  printf 'secret\n' >"$install_test_root/user-config/secrets.json"
  service_log=$case_dir/unsafe-user-ancestor/service.log
  : >"$service_log"
  if TUIBOX_TEST_USER_DATA_DIR="$case_dir/unsafe-user-ancestor/writable/user-data" \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1
  then
    printf 'writable user data ancestor was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
  chmod 0700 "$case_dir/unsafe-user-ancestor/writable"

  install_test_root=$case_dir/relative-user-path/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  prepare_user_state "$install_test_root"
  service_log=$case_dir/relative-user-path/service.log
  : >"$service_log"
  if TUIBOX_TEST_USER_DATA_DIR=relative/user-data \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1
  then
    printf 'relative user data path was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
}

test_uninstall_overlap_preflight() {
  case_dir=$1
  case_fixture=$2

  install_test_root=$case_dir/state-run/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  prepare_user_state "$install_test_root"
  service_log=$case_dir/state-run/service.log
  : >"$service_log"
  if TUIBOX_TEST_STATE_DIR="$install_test_root/run" \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1
  then
    printf 'overlapping state and runtime paths were accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"

  install_test_root=$case_dir/user-system/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  mkdir -p "$install_test_root/user-config"
  printf 'secret\n' >"$install_test_root/user-config/secrets.json"
  service_log=$case_dir/user-system/service.log
  : >"$service_log"
  if TUIBOX_TEST_USER_DATA_DIR="$install_test_root/prefix/libexec/tuibox" \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1
  then
    printf 'overlapping user data and system paths were accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
}

test_uninstall_linux_service_stop() {
  case_dir=$1
  case_fixture=$2

  install_test_root=$case_dir/stop-failure/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  service_log=$case_dir/stop-failure/service.log
  : >"$service_log"
  if TUIBOX_TEST_UNINSTALL_SERVICE_MODE=stop-failure \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" >/dev/null 2>&1
  then
    printf 'genuine systemd stop failure was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  grep -Fx 'disable --now tuiboxd.service' "$service_log" >/dev/null || {
    printf 'systemd stop was not attempted\n' >&2
    return 1
  }
  grep -Fx 'show --property=LoadState --value tuiboxd.service' "$service_log" >/dev/null || {
    printf 'systemd stop failure was not classified\n' >&2
    return 1
  }

  install_test_root=$case_dir/still-active/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  service_log=$case_dir/still-active/service.log
  : >"$service_log"
  if TUIBOX_TEST_UNINSTALL_SERVICE_MODE=still-active \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" >/dev/null 2>&1
  then
    printf 'active systemd service after stop was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  grep -Fx 'show --property=ActiveState --value tuiboxd.service' "$service_log" >/dev/null || {
    printf 'systemd inactive state was not verified\n' >&2
    return 1
  }

  install_test_root=$case_dir/not-found/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  service_log=$case_dir/not-found/service.log
  : >"$service_log"
  TUIBOX_TEST_UNINSTALL_SERVICE_MODE=not-found \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" >/dev/null
  assert_no_installed_files "$install_test_root"
  grep -Fx 'disable --now tuiboxd.service' "$service_log" >/dev/null || {
    printf 'systemd not-found stop was not attempted\n' >&2
    return 1
  }
  grep -Fx 'show --property=LoadState --value tuiboxd.service' "$service_log" >/dev/null || {
    printf 'systemd not-found state was not verified\n' >&2
    return 1
  }
}

test_uninstall_darwin_service_stop() {
  case_dir=$1
  case_fixture=$2

  install_test_root=$case_dir/stop-failure/install
  run_install_platform "$install_test_root" "$case_fixture" darwin "${case_fixture%/*}" >/dev/null
  service_log=$case_dir/stop-failure/service.log
  : >"$service_log"
  if TUIBOX_TEST_UNINSTALL_SERVICE_MODE=launchd-stop-failure \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall_platform "$install_test_root" "$case_fixture" darwin >/dev/null 2>&1
  then
    printf 'genuine launchd bootout failure was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root" darwin
  grep -Fx 'bootout system/io.github.rezraf.tuiboxd' "$service_log" >/dev/null || {
    printf 'launchd bootout was not attempted\n' >&2
    return 1
  }
  grep -Fx 'print system/io.github.rezraf.tuiboxd' "$service_log" >/dev/null || {
    printf 'launchd stop failure was not classified\n' >&2
    return 1
  }

  install_test_root=$case_dir/still-active/install
  run_install_platform "$install_test_root" "$case_fixture" darwin "${case_fixture%/*}" >/dev/null
  service_log=$case_dir/still-active/service.log
  : >"$service_log"
  if TUIBOX_TEST_UNINSTALL_SERVICE_MODE=launchd-still-active \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall_platform "$install_test_root" "$case_fixture" darwin >/dev/null 2>&1
  then
    printf 'loaded launchd service after bootout was accepted\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root" darwin

  install_test_root=$case_dir/not-found/install
  run_install_platform "$install_test_root" "$case_fixture" darwin "${case_fixture%/*}" >/dev/null
  service_log=$case_dir/not-found/service.log
  : >"$service_log"
  TUIBOX_TEST_UNINSTALL_SERVICE_MODE=launchd-not-found \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall_platform "$install_test_root" "$case_fixture" darwin >/dev/null
  assert_no_installed_files "$install_test_root"
  grep -Fx 'bootout system/io.github.rezraf.tuiboxd' "$service_log" >/dev/null || {
    printf 'launchd not-found bootout was not attempted\n' >&2
    return 1
  }
  grep -Fx 'print system/io.github.rezraf.tuiboxd' "$service_log" >/dev/null || {
    printf 'launchd not-found state was not verified\n' >&2
    return 1
  }
}

test_uninstall_path_replacement() {
  case_dir=$1
  case_fixture=$2

  install_test_root=$case_dir/system-path/install
  outside_dir=$case_dir/system-path/outside
  mkdir -p "$outside_dir"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  for name in tuibox tuiboxd tuibox-update-helper sing-box; do
    printf 'outside-%s\n' "$name" >"$outside_dir/$name"
  done
  service_log=$case_dir/system-path/service.log
  : >"$service_log"
  replace_path=$install_test_root/prefix/libexec/tuibox
  if TUIBOX_TEST_UNINSTALL_REPLACE_PATH="$replace_path" \
    TUIBOX_TEST_UNINSTALL_REPLACE_WITH="$outside_dir" \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" >/dev/null 2>&1
  then
    printf 'system path replacement during service stop was accepted\n' >&2
    return 1
  fi
  test -L "$replace_path" && test -d "$replace_path.before" || {
    printf 'system path replacement injection did not run\n' >&2
    return 1
  }
  for name in tuibox tuiboxd tuibox-update-helper sing-box; do
    grep -Fx "outside-$name" "$outside_dir/$name" >/dev/null || {
      printf 'replacement target was mutated: %s\n' "$outside_dir/$name" >&2
      return 1
    }
    test -f "$replace_path.before/$name" || {
      printf 'original managed file was deleted after path replacement: %s\n' "$name" >&2
      return 1
    }
  done
  test -f "$install_test_root/systemd/tuiboxd.service" || {
    printf 'service file was deleted after path replacement\n' >&2
    return 1
  }

  install_test_root=$case_dir/user-path/install
  outside_dir=$case_dir/user-path/outside
  mkdir -p "$outside_dir"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  prepare_user_state "$install_test_root"
  printf 'outside-state\n' >"$outside_dir/state.json"
  service_log=$case_dir/user-path/service.log
  : >"$service_log"
  replace_path=$install_test_root/user-data
  if TUIBOX_TEST_UNINSTALL_REPLACE_PATH="$replace_path" \
    TUIBOX_TEST_UNINSTALL_REPLACE_WITH="$outside_dir" \
    TUIBOX_TEST_SERVICE_LOG="$service_log" \
    run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1
  then
    printf 'user path replacement during service stop was accepted\n' >&2
    return 1
  fi
  test -L "$replace_path" && test -d "$replace_path.before" || {
    printf 'user path replacement injection did not run\n' >&2
    return 1
  }
  grep -Fx 'outside-state' "$outside_dir/state.json" >/dev/null || {
    printf 'replacement user-data target was mutated\n' >&2
    return 1
  }
  test -f "$replace_path.before/state.json" || {
    printf 'original user state was deleted after path replacement\n' >&2
    return 1
  }
  assert_install_intact "$install_test_root"
}

test_uninstall_purge_known_entries() {
  case_dir=$1
  case_fixture=$2
  token=0123456789abcdef0123456789abcdef

  install_test_root=$case_dir/symlink-entry/install
  outside_file=$case_dir/symlink-entry/outside-config
  mkdir -p "$case_dir/symlink-entry"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  prepare_user_state "$install_test_root"
  printf 'outside-config\n' >"$outside_file"
  ln -s "$outside_file" "$install_test_root/state/config-$token.json"
  service_log=$case_dir/symlink-entry/service.log
  : >"$service_log"
  if TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null 2>&1; then
    printf 'symlinked runtime config entry was accepted for purge\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root"
  assert_service_stop_not_attempted "$service_log"
  grep -Fx 'outside-config' "$outside_file" >/dev/null || {
    printf 'symlinked runtime config target was mutated\n' >&2
    return 1
  }

  install_test_root=$case_dir/known-only/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  prepare_user_state "$install_test_root"
  printf 'config\n' >"$install_test_root/state/config-$token.json"
  printf 'temporary\n' >"$install_test_root/state/.config-$token.tmp"
  printf 'unrelated\n' >"$install_test_root/state/config-not-a-tuibox-token.json"
  printf 'unrelated\n' >"$install_test_root/state/.config-short.tmp"
  mkdir -p "$install_test_root/state/nested"
  printf 'nested\n' >"$install_test_root/state/nested/config-$token.json"
  printf 'user-unrelated\n' >"$install_test_root/user-data/unrelated-user-file"
  printf 'config-unrelated\n' >"$install_test_root/user-config/unrelated-config-file"
  service_log=$case_dir/known-only/service.log
  : >"$service_log"
  TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall "$install_test_root" "$case_fixture" --purge-state >/dev/null
  test ! -e "$install_test_root/state/config-$token.json"
  test ! -e "$install_test_root/state/.config-$token.tmp"
  test -f "$install_test_root/state/config-not-a-tuibox-token.json" || {
    printf 'unrelated runtime JSON file was removed\n' >&2
    return 1
  }
  test -f "$install_test_root/state/.config-short.tmp" || {
    printf 'unrelated runtime temporary file was removed\n' >&2
    return 1
  }
  test -f "$install_test_root/state/nested/config-$token.json" || {
    printf 'nested unrelated runtime file was removed\n' >&2
    return 1
  }
  test ! -e "$install_test_root/user-data/state.json"
  test ! -e "$install_test_root/user-data/.state.lock"
  test ! -e "$install_test_root/user-config/secrets.json"
  test ! -e "$install_test_root/user-config/.secrets.lock"
  test -f "$install_test_root/user-data/unrelated-user-file"
  test -f "$install_test_root/user-config/unrelated-config-file"
}

test_uninstall_preserves_state() {
  case_dir=$1
  case_fixture=$2
  token=0123456789abcdef0123456789abcdef
  install_test_root=$case_dir/install
  run_install "$install_test_root" "$case_fixture" >/dev/null
  prepare_user_state "$install_test_root"
  printf 'config\n' >"$install_test_root/state/config-$token.json"
  printf 'runtime-unrelated\n' >"$install_test_root/run/unrelated-runtime-file"
  printf 'install-unrelated\n' >"$install_test_root/prefix/libexec/tuibox/unrelated-install-file"
  service_log=$case_dir/service.log
  : >"$service_log"
  TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall "$install_test_root" "$case_fixture" >/dev/null
  test -f "$install_test_root/state/config-$token.json"
  test -f "$install_test_root/user-data/state.json"
  test -f "$install_test_root/user-data/.state.lock"
  test -f "$install_test_root/user-config/secrets.json"
  test -f "$install_test_root/user-config/.secrets.lock"
  test -f "$install_test_root/run/unrelated-runtime-file"
  test -f "$install_test_root/prefix/libexec/tuibox/unrelated-install-file"
  grep -Fx 'disable --now tuiboxd.service' "$service_log" >/dev/null || {
    printf 'normal uninstall did not stop systemd service\n' >&2
    return 1
  }
  grep -Fx 'show --property=ActiveState --value tuiboxd.service' "$service_log" >/dev/null || {
    printf 'normal uninstall did not verify inactive service\n' >&2
    return 1
  }
}

test_uninstall_sanitizes_path() {
  case_dir=$1
  case_fixture=$2
  install_test_root=$case_dir/install
  malicious_bin=$case_dir/malicious-bin
  marker=$case_dir/untrusted-command-ran
  mkdir -p "$malicious_bin"
  run_install "$install_test_root" "$case_fixture" >/dev/null
  printf '%s\n' \
    '#!/bin/sh' \
    ': >"$TUIBOX_TEST_PATH_MARKER"' \
    'exec /usr/bin/stat "$@"' >"$malicious_bin/stat"
  chmod 755 "$malicious_bin/stat"
  TUIBOX_TEST_PATH="$malicious_bin:/usr/bin:/bin" \
    TUIBOX_TEST_PATH_MARKER="$marker" \
    run_uninstall "$install_test_root" "$case_fixture" >/dev/null
  test ! -e "$marker" || {
    printf 'uninstaller executed a command from untrusted PATH\n' >&2
    return 1
  }
}

test_uninstall_darwin_acl_preflight() {
  case_dir=$1
  case_fixture=$2
  test "$(uname -s)" = Darwin || return 0
  install_test_root=$case_dir/install
  service_log=$case_dir/service.log
  run_install_platform "$install_test_root" "$case_fixture" darwin "${case_fixture%/*}" >/dev/null
  /bin/chmod +a 'everyone allow add_file,delete' "$install_test_root/state"
  : >"$service_log"
  if TUIBOX_TEST_SERVICE_LOG="$service_log" run_uninstall_platform "$install_test_root" "$case_fixture" darwin >/dev/null 2>&1; then
    printf 'writable macOS ACL was accepted on an uninstall path\n' >&2
    return 1
  fi
  assert_install_intact "$install_test_root" darwin
  assert_service_stop_not_attempted "$service_log"
  /bin/chmod -N "$install_test_root/state"
}

run_transaction_case() {
  transaction_case=$1
  transaction_root=$2
  transaction_fixture=$3
  case $transaction_case in
    invalid-template) test_invalid_service_template_preflight "$transaction_root" "$transaction_fixture" ;;
    missing-manager) test_missing_service_manager_preflight "$transaction_root" "$transaction_fixture" ;;
    destination-type) test_destination_type_preflight "$transaction_root" "$transaction_fixture" ;;
    overlapping-destinations) test_overlapping_destination_preflight "$transaction_root" "$transaction_fixture" ;;
    unknown-collisions) test_unknown_managed_collisions "$transaction_root" "$transaction_fixture" ;;
    fresh-activation-failure) test_fresh_activation_failure_rolls_back "$transaction_root" "$transaction_fixture" ;;
    existing-activation-failure) test_existing_activation_failure_restores_install "$transaction_root" ;;
    post-activation-failure) test_post_activation_failure_restores_install "$transaction_root" ;;
    uninstall-missing-home) test_uninstall_missing_home_preflight "$transaction_root" "$transaction_fixture" ;;
    uninstall-path-preflight) test_uninstall_path_preflight "$transaction_root" "$transaction_fixture" ;;
    uninstall-overlap) test_uninstall_overlap_preflight "$transaction_root" "$transaction_fixture" ;;
    uninstall-service-linux) test_uninstall_linux_service_stop "$transaction_root" "$transaction_fixture" ;;
    uninstall-service-darwin) test_uninstall_darwin_service_stop "$transaction_root" "$transaction_fixture" ;;
    uninstall-path-replacement) test_uninstall_path_replacement "$transaction_root" "$transaction_fixture" ;;
    uninstall-purge) test_uninstall_purge_known_entries "$transaction_root" "$transaction_fixture" ;;
    uninstall-preserve) test_uninstall_preserves_state "$transaction_root" "$transaction_fixture" ;;
    uninstall-path-env) test_uninstall_sanitizes_path "$transaction_root" "$transaction_fixture" ;;
    uninstall-darwin-acl) test_uninstall_darwin_acl_preflight "$transaction_root" "$transaction_fixture" ;;
    *) printf 'unknown packaging test case: %s\n' "$transaction_case" >&2; return 1 ;;
  esac
}

make_fixtures "$work_dir/fixture"
if test -n "${TUIBOX_PACKAGING_TEST_CASE:-}"; then
  run_transaction_case "$TUIBOX_PACKAGING_TEST_CASE" "$work_dir/case-$TUIBOX_PACKAGING_TEST_CASE" "$work_dir/fixture"
  printf 'packaging test case passed: %s\n' "$TUIBOX_PACKAGING_TEST_CASE"
  exit 0
fi
for transaction_case in \
  invalid-template \
  missing-manager \
  destination-type \
  overlapping-destinations \
  unknown-collisions \
  fresh-activation-failure \
  existing-activation-failure \
  post-activation-failure \
  uninstall-missing-home \
  uninstall-path-preflight \
  uninstall-overlap \
  uninstall-service-linux \
  uninstall-service-darwin \
  uninstall-path-replacement \
  uninstall-purge \
  uninstall-preserve \
  uninstall-path-env \
  uninstall-darwin-acl
do
  run_transaction_case "$transaction_case" "$work_dir/case-$transaction_case" "$work_dir/fixture"
done

install_root=$work_dir/install
run_install "$install_root" "$work_dir/fixture"
cp "$work_dir/fixture/service-manager" "$root_scope_dir/service-manager"
chmod 755 "$root_scope_dir/service-manager"
(
  TUIBOX_TEST_SERVICE_MANAGER="$root_scope_dir/service-manager" \
    run_install "$root_scope_dir/install" "$work_dir/fixture" / >/dev/null
)

darwin_install_root=$work_dir/darwin-install
run_install_platform "$darwin_install_root" "$work_dir/fixture" darwin

test -f "$root_scope_dir/install/prefix/libexec/tuibox/tuibox"
test -f "$darwin_install_root/launchd/io.github.rezraf.tuiboxd.plist"
for directory in "$install_root/run" "$darwin_install_root/run"; do
  test "$(file_mode "$directory")" = 750 || {
    printf 'installer runtime directory mode is not 0750: %s\n' "$directory" >&2
    exit 1
  }
done
for directory in "$install_root/state" "$darwin_install_root/state"; do
  test "$(file_mode "$directory")" = 700 || {
    printf 'installer state directory mode is not 0700: %s\n' "$directory" >&2
    exit 1
  }
done
(cd "$repo_dir" && TUIBOX_TEST_INSTALLER_RUN_DIR="$install_root/run" go test ./internal/rpc -run '^TestInstallerCreatedSocketDirectorySupportsAuthorizedClient$' -count=1)
for path in \
  "$install_root/prefix/libexec/tuibox/tuibox" \
  "$install_root/prefix/libexec/tuibox/tuiboxd" \
  "$install_root/prefix/libexec/tuibox/tuibox-update-helper" \
  "$install_root/prefix/libexec/tuibox/sing-box" \
  "$install_root/systemd/tuiboxd.service"
do
  test -f "$path" || { printf 'missing installed file: %s\n' "$path" >&2; exit 1; }
done

test -L "$install_root/prefix/bin/tuibox"
test "$(readlink "$install_root/prefix/bin/tuibox")" = "$install_root/prefix/libexec/tuibox/tuibox"
cmp "$install_root/prefix/libexec/tuibox/tuibox" "$install_root/prefix/libexec/tuibox/tuibox-update-helper"
service_file=$install_root/systemd/tuiboxd.service
grep -F -- "--core $install_root/prefix/libexec/tuibox/sing-box" "$service_file" >/dev/null
grep -F -- "--runtime-dir $install_root/state" "$service_file" >/dev/null
grep -F -- "--socket $install_root/run/tuiboxd.sock" "$service_file" >/dev/null
grep -F -- "--socket-gid $(id -g)" "$service_file" >/dev/null
grep -F -- "--allow-uid $(id -u)" "$service_file" >/dev/null

unsupported_root=$work_dir/unsupported
if env TUIBOX_TEST_MODE=1 TUIBOX_OS=windows TUIBOX_ARCH=amd64 TUIBOX_PREFIX="$unsupported_root" sh "$repo_dir/install.sh" >/dev/null 2>&1; then
  printf 'unsupported operating system was accepted\n' >&2
  exit 1
fi

unsafe_parent_root=$work_dir/unsafe-parent-install
mkdir -p "$unsafe_parent_root/prefix"
chmod 0777 "$unsafe_parent_root/prefix"
if run_install "$unsafe_parent_root" "$work_dir/fixture" >/dev/null 2>&1; then
  printf 'writable installation ancestor was accepted\n' >&2
  exit 1
fi

symlink_descendant_root=$work_dir/symlink-descendant-install
mkdir -p "$symlink_descendant_root/prefix" "$symlink_descendant_root/outside-bin"
ln -s "$symlink_descendant_root/outside-bin" "$symlink_descendant_root/prefix/bin"
if run_install "$symlink_descendant_root" "$work_dir/fixture" >/dev/null 2>&1; then
  printf 'symlinked installation descendant was accepted\n' >&2
  exit 1
fi
test ! -e "$symlink_descendant_root/outside-bin/tuibox"

bad_release=$work_dir/bad-release
cp -R "$work_dir/fixture" "$bad_release"
printf '%064d  %s\n' 0 'tuibox_linux_amd64.tar.gz' >"$bad_release/release/checksums.txt"
if run_install "$work_dir/bad-release-install" "$bad_release" >/dev/null 2>&1; then
  printf 'invalid TuiBox checksum was accepted\n' >&2
  exit 1
fi
test ! -e "$work_dir/bad-release-install/prefix/libexec/tuibox/tuibox"

hardlink_release=$work_dir/hardlink-release
mkdir -p "$hardlink_release/release/source" "$hardlink_release/core"
cp "$work_dir/fixture/core/sing-box-1.13.14-linux-amd64.tar.gz" "$hardlink_release/core/"
printf '#!/bin/sh\nprintf shared\n' >"$hardlink_release/release/source/tuibox"
ln "$hardlink_release/release/source/tuibox" "$hardlink_release/release/source/tuiboxd"
chmod 755 "$hardlink_release/release/source/tuibox" "$hardlink_release/release/source/tuiboxd"
(cd "$hardlink_release/release/source" && tar -czf ../tuibox_linux_amd64.tar.gz tuibox tuiboxd)
hardlink_digest=$(sha256_file "$hardlink_release/release/tuibox_linux_amd64.tar.gz")
printf '%s  %s\n' "$hardlink_digest" 'tuibox_linux_amd64.tar.gz' >"$hardlink_release/release/checksums.txt"
if run_install "$work_dir/hardlink-install" "$hardlink_release" >/dev/null 2>&1; then
  printf 'hard-linked release binaries were accepted\n' >&2
  exit 1
fi

bad_core_root=$work_dir/bad-core-install
if env \
  TUIBOX_TEST_MODE=1 TUIBOX_TEST_TRUST_ROOT="$work_dir" TUIBOX_OS=linux TUIBOX_ARCH=amd64 \
  TUIBOX_PREFIX="$bad_core_root/prefix" TUIBOX_ETC_DIR="$bad_core_root/etc" \
  TUIBOX_STATE_DIR="$bad_core_root/state" TUIBOX_RUN_DIR="$bad_core_root/run" \
  TUIBOX_SYSTEMD_DIR="$bad_core_root/systemd" TUIBOX_RELEASE_DIR="$work_dir/fixture/release" \
  TUIBOX_CORE_ARCHIVE="$work_dir/fixture/core/sing-box-1.13.14-linux-amd64.tar.gz" \
  TUIBOX_CORE_SHA256="$(printf '%064d' 0)" TUIBOX_UID=1000 TUIBOX_GID=1000 \
  sh "$repo_dir/install.sh" >/dev/null 2>&1
then
  printf 'invalid core checksum was accepted\n' >&2
  exit 1
fi
test ! -e "$bad_core_root/prefix/libexec/tuibox/sing-box"

mkdir -p "$install_root/user-data" "$install_root/user-config" "$install_root/run"
printf state >"$install_root/user-data/state.json"
printf secret >"$install_root/user-config/secrets.json"
printf unrelated >"$install_root/run/unrelated-runtime-file"
printf unrelated >"$install_root/prefix/libexec/tuibox/unrelated-install-file"
normal_uninstall_log=$work_dir/normal-uninstall-service.log
: >"$normal_uninstall_log"
TUIBOX_TEST_SERVICE_LOG="$normal_uninstall_log" run_uninstall "$install_root" "$work_dir/fixture"
test -f "$install_root/user-data/state.json"
test -f "$install_root/user-config/secrets.json"
test -f "$install_root/run/unrelated-runtime-file"
test -f "$install_root/prefix/libexec/tuibox/unrelated-install-file"
test ! -e "$install_root/prefix/libexec/tuibox/tuibox"
test ! -e "$install_root/systemd/tuiboxd.service"

run_install "$install_root" "$work_dir/fixture"
printf unrelated >"$install_root/user-data/unrelated-user-file"
printf unrelated >"$install_root/user-config/unrelated-config-file"
purge_uninstall_log=$work_dir/purge-uninstall-service.log
: >"$purge_uninstall_log"
TUIBOX_TEST_SERVICE_LOG="$purge_uninstall_log" run_uninstall "$install_root" "$work_dir/fixture" --purge-state
test ! -e "$install_root/user-data/state.json"
test ! -e "$install_root/user-config/secrets.json"
test -f "$install_root/user-data/unrelated-user-file"
test -f "$install_root/user-config/unrelated-config-file"
test ! -e "$install_root/state"

if env TUIBOX_TEST_MODE=1 TUIBOX_OS=linux sh "$repo_dir/uninstall.sh" --unknown >/dev/null 2>&1; then
  printf 'unknown uninstall argument was accepted\n' >&2
  exit 1
fi

uninstall_symlink_root=$work_dir/uninstall-symlink
mkdir -p "$uninstall_symlink_root/prefix/libexec" "$uninstall_symlink_root/outside" "$uninstall_symlink_root/systemd" "$uninstall_symlink_root/run"
printf unrelated >"$uninstall_symlink_root/outside/tuibox"
ln -s "$uninstall_symlink_root/outside" "$uninstall_symlink_root/prefix/libexec/tuibox"
if run_uninstall "$uninstall_symlink_root" "$work_dir/fixture" >/dev/null 2>&1; then
  printf 'symlinked uninstall layout was accepted\n' >&2
  exit 1
fi
test -f "$uninstall_symlink_root/outside/tuibox"

printf 'packaging shell tests passed\n'
