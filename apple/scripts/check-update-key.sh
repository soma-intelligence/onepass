#!/usr/bin/env bash
# Xcode build phase of OnePass, run before its sources (also runnable by hand
# with the build settings in the environment): fails a Mac build signed
# "Developer ID Application" (the build that ships outside the App Store and
# updates itself through Sparkle) when
#   ONEPASS_SPARKLE_PUBLIC_KEY  is not a base64 Ed25519 public key (32 bytes),
#   ONEPASS_UPDATE_FEED_URL     is not an https URL.
# Development, ad hoc and iOS builds pass without a key: their updater stays
# off. The release workflow passes the key on the xcodebuild command line
# (docs/security/release-pipeline.md); tests: scripts/test_appcast.py.
set -euo pipefail

[ "${PLATFORM_NAME:-}" = macosx ] || exit 0
case "${CODE_SIGN_IDENTITY:-}" in
  "Developer ID Application"*) ;;
  *) exit 0 ;;
esac

status=0
key="${ONEPASS_SPARKLE_PUBLIC_KEY:-}"
if ! printf '%s' "$key" | grep -Eq '^[A-Za-z0-9+/]{43}=$' \
  || [ "$(printf '%s' "$key" | base64 --decode 2>/dev/null | wc -c | tr -d ' ')" != 32 ]; then
  echo "error: ONEPASS_SPARKLE_PUBLIC_KEY must be the base64 Ed25519 public key (32 bytes) of the update" \
    "signing key for a Developer ID build; got '${key}'. See docs/security/release-pipeline.md." >&2
  status=1
fi
case "${ONEPASS_UPDATE_FEED_URL:-}" in
  https://?*) ;;
  *)
    echo "error: ONEPASS_UPDATE_FEED_URL must be an https URL for a Developer ID build; got '${ONEPASS_UPDATE_FEED_URL:-}'." >&2
    status=1
    ;;
esac
exit $status
