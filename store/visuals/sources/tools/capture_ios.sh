#!/usr/bin/env bash
# capture_ios.sh <udid> <prefix> <name> <wait-seconds> [extra launch args...]
# Launches the Debug build with the fictional demo data in English and saves a simulator screenshot.
set -uo pipefail
UDID="$1"; PREFIX="$2"; NAME="$3"; WAIT="$4"; shift 4
OUT="$(cd "$(dirname "$0")/.." && pwd)/shots"
mkdir -p "$OUT"
BID="${BID:-me.somalabs.onepass}"
xcrun simctl status_bar "$UDID" override --time 9:41 --batteryState charged --batteryLevel 100 --cellularBars 4 --wifiBars 3 || echo "status bar override failed" >&2
xcrun simctl terminate "$UDID" "$BID" || echo "status bar override failed" >&2
xcrun simctl launch "$UDID" "$BID" -AppleLanguages "(en)" -AppleLocale en_US -OnePassDemoData YES "$@" >/dev/null
sleep "$WAIT"
xcrun simctl io "$UDID" screenshot --type=png "$OUT/$PREFIX-$NAME.png" >/dev/null 2>&1
echo "$OUT/$PREFIX-$NAME.png"
