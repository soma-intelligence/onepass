#!/usr/bin/env bash
# Screenshots of OnePass for the visual review, with the demonstration data
# (Debug builds only, fictional values, password demo-onepass-2026).
#
#   screenshots.sh <folder>      (or: make -C apple screenshots OUT=<folder>)
#
# Screens: Bienvenue, verrouillé, liste, détail, édition, réglages.
# - iPhone (`OnePass M2 iPhone`), light and dark, and iPad (`OnePass M2 iPad`)
#   in landscape, light and dark: the XCUITest `ScreenshotUITests`, which
#   turns the device and switches the appearance itself (simctl has no rotate
#   command). It writes into a temporary folder; this script copies the PNGs.
# - Mac: `screencapture` is refused on the development host, so the app's own
#   Debug snapshot mode is used instead (`-OnePassSnapshot <folder>`,
#   App/Root/Snapshot.swift): it renders its window with `cacheDisplay` (no
#   screen recording permission), light then dark, then quits. The app is
#   sandboxed, so the PNGs land in its container
#   (~/Library/Containers/me.somalabs.onepass/Data/tmp/OnePassSnapshot) and are
#   copied from there.
#
# The folder must be outside the repository. Only the two dedicated
# simulators are used; the iPad one is shut down again if this script booted it.
set -euo pipefail

if [ $# -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <output folder outside the repository>" >&2
  exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$APPLE_DIR/.." && pwd)"

mkdir -p "$1"
OUT="$(cd "$1" && pwd -P)"
ROOT_REAL="$(cd "$ROOT_DIR" && pwd -P)"
case "$OUT/" in
  "$ROOT_REAL"/*)
    echo "refused: $OUT is inside the repository" >&2
    exit 64
    ;;
esac

IPHONE="OnePass M2 iPhone"
IPAD="OnePass M2 iPad"
DERIVED="$APPLE_DIR/DerivedData"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/onepass-shots.XXXXXX")"
IPAD_WAS_BOOTED=1

cleanup() {
  # Shut the iPad simulator down again only if this script booted it (never any other simulator).
  if [ "$IPAD_WAS_BOOTED" = 0 ] && booted "$IPAD"; then
    local udid
    udid="$(udid_of "$IPAD")"
    [ -n "$udid" ] && xcrun simctl shutdown "$udid" || true
  fi
  rm -rf "$STAGING"
}
trap cleanup EXIT

make -C "$APPLE_DIR" core simulators

udid_of() {
  xcrun simctl list devices | grep -F "$1 (" | head -1 | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/'
}

booted() {
  xcrun simctl list devices | grep -F "$1 (" | grep -q "(Booted)"
}

# One xcodebuild run of the screenshot test on one dedicated simulator.
capture_ios() {
  local name="$1" device="$2" landscape="$3"
  echo "screenshots: $name ($device)"
  (cd "$APPLE_DIR" && \
    TEST_RUNNER_ONEPASS_SCREENSHOT_DIR="$STAGING" \
    TEST_RUNNER_ONEPASS_SCREENSHOT_DEVICE="$device" \
    TEST_RUNNER_ONEPASS_SCREENSHOT_LANDSCAPE="$landscape" \
    xcodebuild -project OnePass.xcodeproj -scheme OnePass \
      -destination "platform=iOS Simulator,name=$name" -derivedDataPath "$DERIVED" \
      CODE_SIGN_IDENTITY=- \
      -only-testing:OnePassUITests/ScreenshotUITests test -quiet)
  # Kept even if a later device fails.
  cp "$STAGING"/*.png "$OUT"/ 2>/dev/null || true
}

capture_ios "$IPHONE" iphone 0

booted "$IPAD" || IPAD_WAS_BOOTED=0
capture_ios "$IPAD" ipad 1

# Mac: Debug build, then the snapshot mode.
echo "screenshots: Mac"
(cd "$APPLE_DIR" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= build -quiet)
MAC_APP="$DERIVED/Build/Products/Debug/OnePass.app"
CONTAINER_SHOTS="$HOME/Library/Containers/me.somalabs.onepass/Data/tmp/OnePassSnapshot"
MAC_STAGING="$STAGING/mac"
mkdir -p "$MAC_STAGING"
# Only the files this mode writes, from an earlier run.
rm -f "$CONTAINER_SHOTS"/mac-*.png "$CONTAINER_SHOTS/trace.txt"

"$MAC_APP/Contents/MacOS/OnePass" -ApplePersistenceIgnoreState YES -OnePassSnapshot "$MAC_STAGING" \
  >/dev/null 2>&1 &
MAC_PID=$!
for _ in $(seq 1 180); do
  kill -0 "$MAC_PID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$MAC_PID" 2>/dev/null; then
  echo "screenshots: the Mac app did not quit, stopping it (pid $MAC_PID)" >&2
  kill "$MAC_PID" || true
fi
wait "$MAC_PID" 2>/dev/null || true
if ! ls "$MAC_STAGING"/mac-*.png >/dev/null 2>&1 && [ -d "$CONTAINER_SHOTS" ]; then
  cp "$CONTAINER_SHOTS"/mac-*.png "$MAC_STAGING"/ 2>/dev/null || true
fi

cp "$MAC_STAGING"/*.png "$OUT"/ 2>/dev/null || true

COUNT="$(find "$OUT" -maxdepth 1 -name '*.png' | wc -l | tr -d ' ')"
echo "screenshots: $COUNT PNG in $OUT"
ls -1 "$OUT"
