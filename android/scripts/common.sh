# shellcheck shell=bash
# Shared setup for the Android core scripts: paths, pinned versions, NDK.
# Sourced, not run.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=android/scripts/versions.env
. "$repo_root/android/scripts/versions.env"

if [ -z "${ANDROID_HOME:-}" ]; then
  if [ -n "${ANDROID_SDK_ROOT:-}" ]; then
    ANDROID_HOME="$ANDROID_SDK_ROOT"
  elif [ -d "$HOME/Library/Android/sdk" ]; then
    ANDROID_HOME="$HOME/Library/Android/sdk"
  elif [ -d "$HOME/Android/Sdk" ]; then
    ANDROID_HOME="$HOME/Android/Sdk"
  else
    echo "ANDROID_HOME is not set and no Android SDK was found" >&2
    exit 1
  fi
fi
export ANDROID_HOME

# Always the pinned NDK, whatever else is installed (aws-lc-sys and
# libsqlite3-sys compile C through its clang).
ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$ANDROID_NDK_VERSION"
if [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "NDK $ANDROID_NDK_VERSION missing: sdkmanager --install \"ndk;$ANDROID_NDK_VERSION\"" >&2
  exit 1
fi
export ANDROID_NDK_HOME
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"

if ! cargo ndk --version 2>/dev/null | grep -qx "cargo-ndk $CARGO_NDK_VERSION"; then
  echo "cargo-ndk $CARGO_NDK_VERSION missing: cargo install cargo-ndk --version $CARGO_NDK_VERSION --locked" >&2
  exit 1
fi

# RUSTFLAGS in the environment would replace the 16 KiB page flag of
# core/.cargo/config.toml without a word: refuse it.
if [ -n "${RUSTFLAGS:-}" ] || [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
  echo "unset RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS: they override core/.cargo/config.toml" >&2
  exit 1
fi

ndk_bin() {
  local host
  for host in darwin-x86_64 linux-x86_64; do
    if [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin" ]; then
      printf '%s' "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin"
      return
    fi
  done
  echo "no NDK LLVM toolchain found in $ANDROID_NDK_HOME" >&2
  exit 1
}

# Fails unless every LOAD segment of the ELF file is aligned to 16 KiB
# (Android 15+ devices with 16 KiB pages refuse anything less).
check_page_alignment() {
  local so="$1" readelf aligns
  readelf="$(ndk_bin)/llvm-readelf"
  aligns="$("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }')"
  if [ -z "$aligns" ]; then
    echo "no LOAD segment in $so" >&2
    return 1
  fi
  if printf '%s\n' "$aligns" | grep -qvx '0x4000'; then
    echo "LOAD segments of $so not aligned to 16 KiB:" >&2
    printf '%s\n' "$aligns" >&2
    return 1
  fi
  echo "16 KiB aligned: $so"
}
