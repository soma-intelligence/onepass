#!/usr/bin/env bash
# Xcode build phase of OnePass (macOS only): builds the MCP relay
# (core/onepass-mcp-relay, binary `onepass-mcp`) and embeds it in
# Contents/Helpers. MCP clients launch it; it relays to the app's MCP socket
# and runs, for the sandboxed app, the commands and file writes of the secret
# tools (spec 2026-10-27-m7-app, section 4.1). The app serves only this exact
# binary: its identity is checked against the file in its own bundle.
set -euo pipefail

if [ "${PLATFORM_NAME:-}" != macosx ]; then
  exit 0
fi

export PATH="$HOME/.cargo/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
CORE_DIR="${PROJECT_DIR}/../core"
DEST_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Helpers"
RELAY="$DEST_DIR/onepass-mcp"

if [ "${CONFIGURATION:-Debug}" = Debug ]; then
  PROFILE=debug
  PROFILE_ARGS=()
else
  PROFILE=release
  PROFILE_ARGS=(--release)
fi

# -p only: no dev feature of another crate is unified into the relay.
cargo build --locked --manifest-path "$CORE_DIR/Cargo.toml" -p onepass-mcp-relay \
  ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} --target aarch64-apple-darwin

mkdir -p "$DEST_DIR"
cp "$CORE_DIR/target/aarch64-apple-darwin/$PROFILE/onepass-mcp" "$RELAY"
chmod 755 "$RELAY"

# Signed with the app's identity (ad hoc when the build has none), hardened
# runtime on, before Xcode signs the app around it.
IDENTITY="${EXPANDED_CODE_SIGN_IDENTITY:-}"
if [ "${CODE_SIGNING_ALLOWED:-YES}" != YES ] || [ -z "$IDENTITY" ]; then
  IDENTITY=-
fi
codesign --force --sign "$IDENTITY" --options runtime --timestamp=none \
  --identifier me.somalabs.onepass.mcp-relay "$RELAY"
