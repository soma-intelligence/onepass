#!/usr/bin/env bash
# Builds the Rust core (onepass-ffi) into an XCFramework and generates the
# Swift bindings.
#
#   build-core.sh shipped   release, no dev-fast-kdf, ios-arm64 +
#                           ios-arm64-simulator + macos-arm64 + watchos-arm64 +
#                           watchos-arm64-simulator + xros-arm64 +
#                           xros-arm64-simulator
#                           -> apple/build/OnePassFFI.xcframework
#   build-core.sh dev       debug profile, no dev-fast-kdf, macos-arm64 +
#                           ios-arm64-simulator + watchos-arm64-simulator:
#                           minutes instead of the shipped hour, for Mac and
#                           Simulator app builds (device and visionOS builds
#                           need shipped)
#                           -> apple/build/OnePassFFI.xcframework
#   build-core.sh test      macOS arm64 only, debug profile + dev-fast-kdf
#                           -> apple/build/test/OnePassFFI.xcframework
#
# Idempotent: nothing is rebuilt while the stamp next to the XCFramework
# (.core-stamp) matches: mode, profile, features, target list, rustc version,
# RUSTFLAGS, this script and every file under core/ (.rs, Cargo.toml,
# Cargo.lock, uniffi.toml, data files). One stamp per output directory.
# Always builds with `-p onepass-ffi`, never `--workspace`, so the CLI's
# dev-fast-kdf feature is never unified into a shipped build.
set -euo pipefail

MODE="${1:-shipped}"
case "$MODE" in
  shipped | dev | test) ;;
  *) echo "usage: $0 [shipped|dev|test]" >&2; exit 64 ;;
esac

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$APPLE_DIR/.." && pwd)"

# The sccache server must start before the deployment targets below are
# exported: a server started by one of this script's compiles would keep all
# four in its environment ("conflicting deployment targets" in aws-lc).
if [ "${RUSTC_WRAPPER:-}" = sccache ] || [ "${RUSTC_WRAPPER:-}" = "$(command -v sccache 2>/dev/null)" ]; then
  "$ROOT_DIR/scripts/sccache-start.sh" || true
fi

# Match the package deployment targets so the linker does not warn about
# objects built for a newer OS (C code in aws-lc and SQLite follows these).
export MACOSX_DEPLOYMENT_TARGET=26.0
export IPHONEOS_DEPLOYMENT_TARGET=26.0
export WATCHOS_DEPLOYMENT_TARGET=26.0
export XROS_DEPLOYMENT_TARGET=26.0
CORE_DIR="$ROOT_DIR/core"
TARGET_DIR="${ONEPASS_CORE_TARGET_DIR:-$CORE_DIR/target}"
# Cargo writes where this script reads the libraries back. An inherited
# CARGO_TARGET_DIR (one shared between clones, say) would make it link another
# checkout's libonepass_ffi.a against this checkout's Swift bindings.
export CARGO_TARGET_DIR="$TARGET_DIR"
SWIFT_OUT="$APPLE_DIR/VaultKit/Sources/OnePassCore"

if [ "$MODE" = shipped ]; then
  OUT_DIR="$APPLE_DIR/build"
  TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin
    aarch64-apple-watchos aarch64-apple-watchos-sim aarch64-apple-visionos aarch64-apple-visionos-sim)
  PROFILE_DIR=release
  CARGO_ARGS=(--release)
elif [ "$MODE" = dev ]; then
  OUT_DIR="$APPLE_DIR/build"
  TARGETS=(aarch64-apple-darwin aarch64-apple-ios-sim aarch64-apple-watchos-sim)
  PROFILE_DIR=debug
  CARGO_ARGS=()
else
  OUT_DIR="$APPLE_DIR/build/test"
  TARGETS=(aarch64-apple-darwin)
  PROFILE_DIR=debug
  CARGO_ARGS=(--features dev-fast-kdf)
fi
XCFRAMEWORK="$OUT_DIR/OnePassFFI.xcframework"
STAMP="$OUT_DIR/.core-stamp"

# Every file under core/ except build output and fuzz scratch: Rust sources,
# manifests, lockfile, rust-toolchain.toml, .cargo config, and data files
# pulled in with include_str!. NUL-safe and sorted.
fingerprint() {
  (
    cd "$CORE_DIR"
    find . \
      \( -path ./target -o -path ./fuzz/target -o -path ./fuzz/corpus \
         -o -path ./fuzz/artifacts -o -name .DS_Store \) -prune -o \
      -type f -print0 \
      | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | cut -d' ' -f1
  )
  # A different script also invalidates the output.
  shasum -a 256 "$SCRIPT_DIR/build-core.sh" | cut -d' ' -f1
}
# Everything that decides what the XCFramework contains. shipped and dev share
# an output directory and test has its own: the mode, profile, features and
# target list are all in the stamp, so a test (dev-fast-kdf) build is never
# taken for a dev or shipped one, and switching modes always rebuilds. The
# toolchain (rust-toolchain.toml picks it in core/) and RUSTFLAGS count too.
stamp_content() {
  echo "mode: $MODE"
  echo "profile: $PROFILE_DIR"
  echo "cargo args: ${CARGO_ARGS[*]-}"
  echo "targets: ${TARGETS[*]}"
  echo "rustflags: ${RUSTFLAGS:-} ${CARGO_ENCODED_RUSTFLAGS:-}"
  (cd "$CORE_DIR" && rustc -vV) | sed 's/^/rustc /'
  echo "sources: $(fingerprint | tr '\n' ' ')"
}
CURRENT="$(stamp_content)"

# dev and shipped must never carry the dev KDF floor, cached or not: checked
# before the stamp, so even an up-to-date build is refused if the graph
# changed underneath it.
if [ "$MODE" != test ] \
  && (cd "$CORE_DIR" && cargo tree -p onepass-ffi -e features,no-dev -i onepass-core \
        --target aarch64-apple-darwin) | grep -q 'feature "dev-fast-kdf"'; then
  echo "core ($MODE): refusing to build, dev-fast-kdf is enabled in the dependency graph" >&2
  exit 1
fi

if [ -d "$XCFRAMEWORK" ] && [ -f "$SWIFT_OUT/onepass_ffi.swift" ] \
  && [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$CURRENT" ]; then
  # SWIFT_OUT is one file shared by every mode, but the bindings are not identical: the test build
  # (dev-fast-kdf) exports extra functions (testSoftwarePqHalf, ...). Put this mode's bindings back
  # when another mode overwrote them since (make core then make test).
  if [ -f "$OUT_DIR/generated/onepass_ffi.swift" ] \
    && ! cmp -s "$OUT_DIR/generated/onepass_ffi.swift" "$SWIFT_OUT/onepass_ffi.swift"; then
    echo "core ($MODE): restoring this mode's Swift bindings"
    cp "$OUT_DIR/generated/onepass_ffi.swift" "$SWIFT_OUT/onepass_ffi.swift"
  fi
  echo "core ($MODE): up to date (stamp $STAMP)"
  exit 0
fi
[ -f "$STAMP" ] && echo "core ($MODE): stamp differs, rebuilding"

mkdir -p "$OUT_DIR"
rm -f "$STAMP"

# A symlinked target directory is most likely shared with another checkout,
# whose builds would overwrite these libraries between build and packaging.
for dir in "$TARGET_DIR" "${TARGETS[@]/#/$TARGET_DIR/}"; do
  if [ -L "$dir" ]; then
    echo "core: $dir is a symlink; give this checkout its own target directory" \
      "(remove the link, or point ONEPASS_CORE_TARGET_DIR at a real directory)" >&2
    exit 1
  fi
done

echo "core ($MODE): cargo build ${TARGETS[*]}"
# Only the deployment target of the platform being built may be in the
# environment: clang refuses a compile that sees two of them ("conflicting
# deployment targets"), which breaks sccache's compiler detection for aws-lc.
deployment_var() {
  case "$1" in
    *-darwin) echo MACOSX_DEPLOYMENT_TARGET ;;
    *-ios | *-ios-sim) echo IPHONEOS_DEPLOYMENT_TARGET ;;
    *-watchos | *-watchos-sim) echo WATCHOS_DEPLOYMENT_TARGET ;;
    *-visionos | *-visionos-sim) echo XROS_DEPLOYMENT_TARGET ;;
  esac
}
ALL_DEPLOYMENT_VARS=(MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET XROS_DEPLOYMENT_TARGET)

for target in "${TARGETS[@]}"; do
  keep="$(deployment_var "$target")"
  unset_args=()
  for var in "${ALL_DEPLOYMENT_VARS[@]}"; do
    [ "$var" = "$keep" ] || unset_args+=(-u "$var")
  done
  (cd "$CORE_DIR" && env "${unset_args[@]}" cargo build -p onepass-ffi ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"} --target "$target")
done

# Bindings: they depend on the exported interface, which the dev-fast-kdf
# feature extends (test mode). Generated from the macOS static library and
# kept in $OUT_DIR/generated for the cache check above.
MAC_LIB="$TARGET_DIR/aarch64-apple-darwin/$PROFILE_DIR/libonepass_ffi.a"
GEN_DIR="$OUT_DIR/generated"
rm -rf "$GEN_DIR"
mkdir -p "$GEN_DIR" "$SWIFT_OUT"
echo "core ($MODE): generating Swift bindings"
(cd "$CORE_DIR" && env -u IPHONEOS_DEPLOYMENT_TARGET -u WATCHOS_DEPLOYMENT_TARGET -u XROS_DEPLOYMENT_TARGET \
  cargo run -q -p onepass-ffi --features bindgen --bin uniffi-bindgen -- \
  generate --library "$MAC_LIB" --language swift --out-dir "$GEN_DIR")

# Rewrite only on change so SwiftPM does not rebuild for nothing.
if ! cmp -s "$GEN_DIR/onepass_ffi.swift" "$SWIFT_OUT/onepass_ffi.swift"; then
  cp "$GEN_DIR/onepass_ffi.swift" "$SWIFT_OUT/onepass_ffi.swift"
fi

HEADERS="$OUT_DIR/headers"
rm -rf "$HEADERS"
mkdir -p "$HEADERS"
cp "$GEN_DIR/onepass_ffiFFI.h" "$HEADERS/"
cp "$GEN_DIR/onepass_ffiFFI.modulemap" "$HEADERS/module.modulemap"

LIB_ARGS=()
for target in "${TARGETS[@]}"; do
  LIB_ARGS+=(-library "$TARGET_DIR/$target/$PROFILE_DIR/libonepass_ffi.a" -headers "$HEADERS")
done

rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework "${LIB_ARGS[@]}" -output "$XCFRAMEWORK" >/dev/null

echo "$CURRENT" > "$STAMP"
echo "core ($MODE): $XCFRAMEWORK"
