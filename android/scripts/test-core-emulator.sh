#!/usr/bin/env bash
# Builds the test binaries of onepass-core, onepass-ffi and onepass-peer for
# Android, pushes
# them to the running emulator (or device) with adb, runs each one there and
# exits with the status of the first failure. Extra args go to every test
# binary (test name filters).
#
#   android/scripts/test-core-emulator.sh [test binary args...]
#
# ONEPASS_TEST_ABI picks the ABI: x86_64 (default, the CI emulator) or
# arm64-v8a (Apple Silicon emulators, real devices). ANDROID_SERIAL picks the
# device when several are attached.
set -euo pipefail

# shellcheck source=android/scripts/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

abi="${ONEPASS_TEST_ABI:-x86_64}"
case "$abi" in
  x86_64 | arm64-v8a) ;;
  *)
    echo "ONEPASS_TEST_ABI must be x86_64 or arm64-v8a, not $abi" >&2
    exit 2
    ;;
esac

adb="$ANDROID_HOME/platform-tools/adb"
remote=/data/local/tmp/onepass-tests

case "$abi" in
  x86_64) triple=x86_64-linux-android ;;
  arm64-v8a) triple=aarch64-linux-android ;;
esac
triple_env="$(printf '%s' "$triple" | tr '-' '_')"
triple_upper="$(printf '%s' "$triple_env" | tr '[:lower:]' '[:upper:]')"

# Plain cargo with the NDK clang, not `cargo ndk test --no-run`: cargo-ndk 4
# consumes cargo's JSON messages itself, so the test executables it built
# can't be listed. Same NDK, same API level, same rustflags
# (core/.cargo/config.toml) as build-core.sh; its own target directory keeps
# both caches warm.
bin="$(ndk_bin)"
export "CC_$triple_env=$bin/clang"
export "CXX_$triple_env=$bin/clang++"
export "CFLAGS_$triple_env=--target=$triple$ANDROID_MIN_API"
export "CXXFLAGS_$triple_env=--target=$triple$ANDROID_MIN_API"
export "AR_$triple_env=$bin/llvm-ar"
export "RANLIB_$triple_env=$bin/llvm-ranlib"
export "CARGO_TARGET_${triple_upper}_LINKER=$bin/$triple$ANDROID_MIN_API-clang"
export "CARGO_TARGET_${triple_upper}_AR=$bin/llvm-ar"
export CARGO_TARGET_DIR="$repo_root/core/target/android-tests"

cd "$repo_root/core"
build_log="$(mktemp)"
trap 'rm -f "$build_log"' EXIT
cargo test --target "$triple" -p onepass-core -p onepass-ffi -p onepass-peer --no-run --message-format=json-render-diagnostics >"$build_log"
binaries=()
while IFS= read -r exe; do
  binaries+=("$exe")
done < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' "$build_log")
if [ "${#binaries[@]}" -eq 0 ]; then
  echo "no test binary built" >&2
  exit 1
fi

"$adb" wait-for-device
device_abi="$("$adb" shell getprop ro.product.cpu.abi | tr -d '\r')"
if [ "$device_abi" != "$abi" ]; then
  echo "device ABI is $device_abi, binaries are $abi (set ONEPASS_TEST_ABI)" >&2
  exit 1
fi

# adbd restarts on root and unroot: wait (at most 2 minutes) until it
# answers as the wanted uid.
adb_uid() {
  local tries=0
  until [ "$("$adb" shell id -u 2>/dev/null | tr -d '\r')" = "$1" ]; do
    tries=$((tries + 1))
    if [ "$tries" -ge 120 ]; then
      echo "adbd never came back as uid $1" >&2
      return 1
    fi
    sleep 1
  done
}

# The tests run as the shell user (uid 2000), never as root: root would
# bypass the file permission checks some tests make.
if [ "$("$adb" shell id -u | tr -d '\r')" = 0 ]; then
  "$adb" unroot >/dev/null
  adb_uid 2000
fi
"$adb" shell "rm -rf $remote && mkdir -p $remote/bin $remote/tmp"
# frozen_account reads its fixture at run time (ONEPASS_CORE_FIXTURES).
"$adb" push "$repo_root/core/onepass-core/tests/fixtures" "$remote/" >/dev/null

# The adb shell SELinux domain may not create Unix sockets under
# /data/local/tmp (avc: denied { create } ... tclass=sock_file), unlike an
# app in its own data directory. The developer tests bind the SSH agent and
# MCP sockets, so they run with SELinux permissive, on non-user emulator
# builds only, still as the shell user. Every other binary runs enforcing.
needs_sockets='^developer-'
selinux() {
  "$adb" root >/dev/null
  adb_uid 0
  "$adb" shell setenforce "$1"
  "$adb" unroot >/dev/null
  adb_uid 2000
}
# Whatever ends the run (failure, Ctrl-C, kill), never leave the device
# permissive: best effort, only once it was switched.
permissive=0
restore_enforcing() {
  if [ "$permissive" -eq 1 ]; then
    permissive=0
    selinux 1 || echo "could not restore SELinux enforcing: run adb root; adb shell setenforce 1" >&2
  fi
}
trap 'restore_enforcing; rm -f "$build_log"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
build_type="$("$adb" shell getprop ro.build.type | tr -d '\r')"
emulator=0
if [ "$("$adb" shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] ||
  [ "$("$adb" shell getprop ro.boot.qemu | tr -d '\r')" = 1 ]; then
  emulator=1
fi

first_failure=0
passed_total=0
failed_total=0
ignored_total=0
for exe in "${binaries[@]}"; do
  name="$(basename "$exe")"
  "$adb" push "$exe" "$remote/bin/$name" >/dev/null
  echo "=== $name"
  if printf '%s' "$name" | grep -Eq "$needs_sockets"; then
    if [ "$build_type" = user ] || [ "$emulator" -ne 1 ]; then
      echo "$name binds Unix sockets: needs a userdebug or eng emulator (SELinux permissive)" >&2
    else
      echo "(SELinux permissive for $name)"
      permissive=1
      selinux 0
    fi
  fi
  out="$(mktemp)"
  set +e
  "$adb" shell "cd $remote && TMPDIR=$remote/tmp ONEPASS_CORE_FIXTURES=$remote/fixtures RUST_BACKTRACE=1 ./bin/$name $*" 2>&1 | tee "$out"
  status="${PIPESTATUS[0]}"
  set -e
  restore_enforcing
  # Debug test binaries are large: keep the emulator disk free.
  "$adb" shell "rm -f $remote/bin/$name"
  summary="$(grep -E '^test result:' "$out" | tail -n 1 || true)"
  rm -f "$out"
  if [ -n "$summary" ]; then
    passed_total=$((passed_total + $(printf '%s' "$summary" | sed -E 's/.* ([0-9]+) passed.*/\1/')))
    failed_total=$((failed_total + $(printf '%s' "$summary" | sed -E 's/.* ([0-9]+) failed.*/\1/')))
    ignored_total=$((ignored_total + $(printf '%s' "$summary" | sed -E 's/.* ([0-9]+) ignored.*/\1/')))
  fi
  if [ "$status" -ne 0 ]; then
    echo "FAILED: $name (exit $status)" >&2
    if [ "$first_failure" -eq 0 ]; then
      first_failure="$status"
    fi
  fi
done

"$adb" shell "rm -rf $remote"
echo "android $abi: ${#binaries[@]} test binaries, $passed_total passed, $failed_total failed, $ignored_total ignored"
exit "$first_failure"
