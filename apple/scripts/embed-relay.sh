#!/usr/bin/env bash
# Xcode build phase of OnePass (macOS): embeds onepass-relay, the native
# messaging host Chrome and Firefox launch, in Contents/Helpers (spec
# docs/specs/2026-10-27-release-bridge-design.md, P-09).
#
# Only builds signed by a team carry it: the relay reaches the app only
# through the App Group container of its own team and checks the app's
# signature, so an ad hoc relay could reach nothing. It is signed here, before
# Xcode signs the app around it: hardened runtime, the App Group only,
# identifier me.somalabs.onepass.relay (the one the app accepts).
#
# Not sandboxed, on purpose (spec P-09): inside an app bundle the App Sandbox
# refuses a client the code-signature lookup of the listener (EPERM, measured
# 2026-10-27), and the relay must check that the listener is the OnePass app.
# A Mac App Store build would need it sandboxed, without that check.
set -euo pipefail

RELAY="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Helpers/onepass-relay"

if [ "${PLATFORM_NAME:-}" != macosx ]; then
  exit 0
fi
if [ "${CODE_SIGNING_ALLOWED:-NO}" != YES ] || [ -z "${DEVELOPMENT_TEAM:-}" ] \
  || [ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] || [ "${EXPANDED_CODE_SIGN_IDENTITY}" = "-" ]; then
  rm -f "$RELAY"
  exit 0
fi

export PATH="$HOME/.cargo/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
CORE_DIR="${PROJECT_DIR}/../core"

# -p only: no feature of another crate is unified into this build.
cargo build --locked --release --manifest-path "$CORE_DIR/Cargo.toml" -p onepass-relay \
  --target aarch64-apple-darwin

mkdir -p "$(dirname "$RELAY")"
cp "$CORE_DIR/target/aarch64-apple-darwin/release/onepass-relay" "$RELAY"
chmod 755 "$RELAY"

ENTITLEMENTS="${DERIVED_FILE_DIR}/onepass-relay.entitlements"
mkdir -p "$DERIVED_FILE_DIR"
cat > "$ENTITLEMENTS" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${DEVELOPMENT_TEAM}.me.somalabs.onepass</string>
	</array>
</dict>
</plist>
PLIST

TIMESTAMP=--timestamp=none
case "${EXPANDED_CODE_SIGN_IDENTITY_NAME:-}" in
  "Developer ID"*) TIMESTAMP=--timestamp ;;
esac
codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --options runtime "$TIMESTAMP" \
  --identifier me.somalabs.onepass.relay --entitlements "$ENTITLEMENTS" "$RELAY"
