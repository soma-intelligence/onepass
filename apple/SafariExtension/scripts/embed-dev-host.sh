#!/usr/bin/env bash
# Xcode build phase of OnePassSafari: embeds the development native host
# (core/onepass-native-host) in Contents/MacOS when ONEPASS_SAFARI_DEV_HOST is
# YES (Debug only, see project.yml). The handler starts it once per extension
# connection, as Chrome and Firefox do through native messaging. It is a
# development host ("DEV MODE"): never in a Release configuration.
set -euo pipefail

HOST_BIN="${TARGET_BUILD_DIR}/${EXECUTABLE_FOLDER_PATH}/onepass-native-host"

if [ "${ONEPASS_SAFARI_DEV_HOST:-NO}" != YES ]; then
  rm -f "$HOST_BIN"
  exit 0
fi

export PATH="$HOME/.cargo/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
CORE_DIR="${PROJECT_DIR}/../core"

# -p only: the host's dev-fast-kdf feature never leaks into another crate's build.
cargo build --locked --manifest-path "$CORE_DIR/Cargo.toml" -p onepass-native-host \
  --target aarch64-apple-darwin

mkdir -p "$(dirname "$HOST_BIN")"
cp "$CORE_DIR/target/aarch64-apple-darwin/debug/onepass-native-host" "$HOST_BIN"
chmod 755 "$HOST_BIN"

# Signed before Xcode signs the appex around it. A sandboxed appex may only
# start a child that inherits its sandbox.
if [ "${CODE_SIGNING_ALLOWED:-NO}" = YES ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
  codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --options runtime --timestamp=none \
    --entitlements "${PROJECT_DIR}/SafariExtension/Support/DevHost.entitlements" "$HOST_BIN"
fi
