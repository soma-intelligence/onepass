#!/usr/bin/env bash
# Builds libonepass_ffi.so for arm64-v8a and x86_64 into the jniLibs of
# vaultkit-android, then checks the 16 KiB page alignment of each.
#
#   android/scripts/build-core.sh [debug|release]
set -euo pipefail

# shellcheck source=android/scripts/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

profile="${1:-debug}"
case "$profile" in
  debug) profile_flag=() ;;
  release) profile_flag=(--release) ;;
  *)
    echo "usage: $0 [debug|release]" >&2
    exit 2
    ;;
esac

jni_libs="$repo_root/android/vaultkit-android/src/main/jniLibs"

cd "$repo_root/core"
cargo ndk -t arm64-v8a -t x86_64 --platform "$ANDROID_MIN_API" -o "$jni_libs" \
  build -p onepass-ffi ${profile_flag[@]+"${profile_flag[@]}"}

for abi in arm64-v8a x86_64; do
  check_page_alignment "$jni_libs/$abi/libonepass_ffi.so"
done
