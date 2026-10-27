#!/usr/bin/env bash
# Builds the Rust core (onepass-ffi) into an XCFramework and generates the
# Swift bindings.
#
#   build-core.sh shipped   release, no dev-fast-kdf, ios-arm64 +
#                           ios-arm64-simulator + macos-arm64 + watchos-arm64 +
#                           watchos-arm64-simulator + xros-arm64 +
#                           xros-arm64-simulator
#                           -> apple/build/OnePassFFI.xcframework
#   build-core.sh test      macOS arm64 only, debug profile + dev-fast-kdf
#                           -> apple/build/test/OnePassFFI.xcframework
#
# Idempotent: nothing is rebuilt while the fingerprint of the Rust sources
# (.rs, Cargo.toml, Cargo.lock under core/) is unchanged. One stamp per mode.
# Always builds with `-p onepass-ffi`, never `--workspace`, so the CLI's
# dev-fast-kdf feature is never unified into a shipped build.
set -euo pipefail

MODE="${1:-shipped}"
case "$MODE" in
  shipped | test) ;;
  *) echo "usage: $0 [shipped|test]" >&2; exit 64 ;;
esac

export PATH="$HOME/.cargo/bin:$PATH"

# Match the package deployment targets so the linker does not warn about
# objects built for a newer OS (C code in aws-lc and SQLite follows these).
export MACOSX_DEPLOYMENT_TARGET=26.0
export IPHONEOS_DEPLOYMENT_TARGET=26.0
export WATCHOS_DEPLOYMENT_TARGET=26.0
export XROS_DEPLOYMENT_TARGET=26.0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$APPLE_DIR/.." && pwd)"
CORE_DIR="$ROOT_DIR/core"
TARGET_DIR="$CORE_DIR/target"
SWIFT_OUT="$APPLE_DIR/VaultKit/Sources/OnePassCore"

if [ "$MODE" = shipped ]; then
  OUT_DIR="$APPLE_DIR/build"
  TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin
    aarch64-apple-watchos aarch64-apple-watchos-sim aarch64-apple-visionos aarch64-apple-visionos-sim)
  PROFILE_DIR=release
  CARGO_ARGS=(--release)
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
CURRENT="$(fingerprint)"

if [ -d "$XCFRAMEWORK" ] && [ -f "$SWIFT_OUT/onepass_ffi.swift" ] \
  && [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$CURRENT" ]; then
  echo "core ($MODE): up to date"
  exit 0
fi

# A shipped build must never carry the dev KDF floor.
if [ "$MODE" = shipped ] \
  && (cd "$CORE_DIR" && cargo tree -p onepass-ffi -e features,no-dev -i onepass-core \
        --target aarch64-apple-darwin) | grep -q 'feature "dev-fast-kdf"'; then
  echo "core (shipped): refusing to build, dev-fast-kdf is enabled in the dependency graph" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$STAMP"

echo "core ($MODE): cargo build ${TARGETS[*]}"
for target in "${TARGETS[@]}"; do
  (cd "$CORE_DIR" && cargo build -p onepass-ffi "${CARGO_ARGS[@]}" --target "$target")
done

# Bindings: identical for both modes (they only depend on the exported
# interface). Generated from the macOS static library.
MAC_LIB="$TARGET_DIR/aarch64-apple-darwin/$PROFILE_DIR/libonepass_ffi.a"
GEN_DIR="$OUT_DIR/generated"
rm -rf "$GEN_DIR"
mkdir -p "$GEN_DIR" "$SWIFT_OUT"
echo "core ($MODE): generating Swift bindings"
(cd "$CORE_DIR" && cargo run -q -p onepass-ffi --features bindgen --bin uniffi-bindgen -- \
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
