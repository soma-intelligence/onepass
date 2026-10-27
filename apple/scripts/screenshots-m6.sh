#!/usr/bin/env bash
# Milestone 6 screenshots: the Apple Watch app and the Vision Pro app, with fictional data only
# (Debug builds).
#
#   screenshots-m6.sh <folder>      (or: make -C apple screenshots-m6 OUT=<folder>)
#
# - Watch (`OnePass M6 Watch`): `-OnePassWatchDemo YES` (in-memory demo entries, no key). List
#   only: the watch app has no launch argument that opens a detail screen. watchOS has a single
#   (dark) appearance and its simulator refuses `simctl ui appearance`: one shot.
# - Vision Pro (`OnePass M6 Vision Pro`): `-OnePassDemoData YES` (milestone 2 demo base), the
#   list, then the detail of "Forge Atlas" (`-OnePassDemoItem`).
# Each screen in light then dark appearance (`simctl ui <device> appearance`) when the runtime
# supports it. visionOS accepts the setting but its glass window looks the same in both.
#
# The folder must be outside the repository. Only the two dedicated simulators are used: each one
# is booted when needed, its appearance restored, and it is shut down again only if this script
# booted it. Waits can be raised with WATCH_WAIT and VISION_WAIT (seconds).
set -euo pipefail

if [ $# -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <output folder outside the repository>" >&2
  exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$APPLE_DIR/.." && pwd)"

# Checked before anything is created: the resolved destination must be outside this checkout and
# outside the main repository (a worktree lives inside it, under a nested worktree folder).
PARENT="$(dirname "$1")"
if [ ! -d "$PARENT" ]; then
  echo "refused: $PARENT does not exist" >&2
  exit 64
fi
OUT="$(cd "$PARENT" && pwd -P)/$(basename "$1")"
ROOT_REAL="$(cd "$ROOT_DIR" && pwd -P)"
COMMON_DIR="$(cd "$ROOT_DIR" && git rev-parse --git-common-dir 2>/dev/null || true)"
MAIN_REAL=""
if [ -n "$COMMON_DIR" ]; then
  MAIN_REAL="$(cd "$ROOT_DIR" && cd "$COMMON_DIR/.." && pwd -P)"
fi
for repo in "$ROOT_REAL" "$MAIN_REAL"; do
  [ -n "$repo" ] || continue
  case "$OUT/" in
    "$repo"/*)
      echo "refused: $OUT is inside the repository ($repo)" >&2
      exit 64
      ;;
  esac
done
mkdir -p "$OUT"

WATCH="OnePass M6 Watch"
VISION="OnePass M6 Vision Pro"
WATCH_BUNDLE="me.somalabs.onepass.watchkitapp"
VISION_BUNDLE="me.somalabs.onepass"
DERIVED="$APPLE_DIR/DerivedData"
WATCH_WAIT="${WATCH_WAIT:-8}"
VISION_WAIT="${VISION_WAIT:-20}"

udid_of() {
  xcrun simctl list devices | grep -F "$1 (" | head -1 | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/'
}

booted() {
  xcrun simctl list devices | grep -F "$1 (" | grep -q "(Booted)"
}

# Devices this script booted, and the appearance each one had before.
BOOTED_HERE=()
RESTORE_APPEARANCE=()

cleanup() {
  local entry udid appearance
  for entry in ${RESTORE_APPEARANCE[@]+"${RESTORE_APPEARANCE[@]}"}; do
    udid="${entry%%=*}"
    appearance="${entry#*=}"
    case "$appearance" in
      light | dark) xcrun simctl ui "$udid" appearance "$appearance" >/dev/null 2>&1 || true ;;
    esac
  done
  # Never any simulator other than the two dedicated ones, and only if booted here.
  for udid in ${BOOTED_HERE[@]+"${BOOTED_HERE[@]}"}; do
    xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

make -C "$APPLE_DIR" core simulators-m6

for device in "$WATCH" "$VISION"; do
  if [ -z "$(udid_of "$device")" ]; then
    echo "refused: simulator \"$device\" is missing (make -C apple simulators-m6)" >&2
    exit 69
  fi
done
WATCH_UDID="$(udid_of "$WATCH")"
VISION_UDID="$(udid_of "$VISION")"

echo "screenshots-m6: building the watch app"
(cd "$APPLE_DIR" && xcodebuild -project OnePass.xcodeproj -scheme OnePassWatch \
  -destination "platform=watchOS Simulator,id=$WATCH_UDID" -derivedDataPath "$DERIVED" \
  CODE_SIGN_IDENTITY=- build -quiet)
echo "screenshots-m6: building the visionOS app"
(cd "$APPLE_DIR" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
  -destination "platform=visionOS Simulator,id=$VISION_UDID" -derivedDataPath "$DERIVED" \
  CODE_SIGN_IDENTITY=- build -quiet)
WATCH_APP="$DERIVED/Build/Products/Debug-watchsimulator/OnePassWatch.app"
VISION_APP="$DERIVED/Build/Products/Debug-xrsimulator/OnePass.app"

# Boots one dedicated simulator if needed, remembers its appearance, installs the app.
prepare() {
  local udid="$1" app="$2" current
  if ! xcrun simctl list devices | grep -F "($udid)" | grep -q "(Booted)"; then
    xcrun simctl boot "$udid"
    BOOTED_HERE+=("$udid")
  fi
  xcrun simctl bootstatus "$udid" -b >/dev/null
  if current="$(xcrun simctl ui "$udid" appearance 2>/dev/null)"; then
    RESTORE_APPEARANCE+=("$udid=$current")
  fi
  xcrun simctl install "$udid" "$app"
}

# Whether the runtime has light and dark appearances (watchOS does not).
has_appearance() {
  case "$(xcrun simctl ui "$1" appearance 2>/dev/null || true)" in
    light | dark) return 0 ;;
    *) return 1 ;;
  esac
}

# One screenshot: appearance ("-" keeps the system one), fresh launch with the given arguments,
# wait, capture.
shoot() {
  local udid="$1" bundle="$2" wait="$3" appearance="$4" file="$5"
  shift 5
  [ "$appearance" = - ] || xcrun simctl ui "$udid" appearance "$appearance"
  xcrun simctl terminate "$udid" "$bundle" >/dev/null 2>&1 || true
  xcrun simctl launch --terminate-running-process "$udid" "$bundle" "$@" >/dev/null
  sleep "$wait"
  xcrun simctl io "$udid" screenshot --type=png "$OUT/$file" >/dev/null 2>&1
  echo "screenshots-m6: $file"
}

echo "screenshots-m6: $WATCH"
prepare "$WATCH_UDID" "$WATCH_APP"
if has_appearance "$WATCH_UDID"; then
  for appearance in light dark; do
    shoot "$WATCH_UDID" "$WATCH_BUNDLE" "$WATCH_WAIT" "$appearance" "watch-list-$appearance.png" \
      -OnePassWatchDemo YES
  done
else
  shoot "$WATCH_UDID" "$WATCH_BUNDLE" "$WATCH_WAIT" - "watch-list.png" -OnePassWatchDemo YES
fi
xcrun simctl terminate "$WATCH_UDID" "$WATCH_BUNDLE" >/dev/null 2>&1 || true

echo "screenshots-m6: $VISION"
prepare "$VISION_UDID" "$VISION_APP"
for appearance in light dark; do
  shoot "$VISION_UDID" "$VISION_BUNDLE" "$VISION_WAIT" "$appearance" "vision-list-$appearance.png" \
    -OnePassDemoData YES
  shoot "$VISION_UDID" "$VISION_BUNDLE" "$VISION_WAIT" "$appearance" "vision-detail-$appearance.png" \
    -OnePassDemoData YES -OnePassDemoItem "Forge Atlas"
done
xcrun simctl terminate "$VISION_UDID" "$VISION_BUNDLE" >/dev/null 2>&1 || true

COUNT="$(find "$OUT" -maxdepth 1 -name '*.png' | wc -l | tr -d ' ')"
echo "screenshots-m6: $COUNT PNG in $OUT"
ls -1 "$OUT"
