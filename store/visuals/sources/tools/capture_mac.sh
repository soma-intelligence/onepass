#!/usr/bin/env bash
# capture_mac.sh <name> <wait> [args]: the Debug Mac app, copy re-signed as me.somalabs.onepass.visuals
# (own container, never the real app's), demo data in English, light, window captured without shadow.
set -uo pipefail
NAME="$1"; WAIT="$2"; shift 2
D=/private/tmp/claude-501/dd-onepass-visuals; M=$D/OnePassVisuals.app
OUT="$(cd "$(dirname "$0")/.." && pwd)/shots"
pkill -f "$M/Contents/MacOS/OnePass" 2>/dev/null; sleep 2
"$M/Contents/MacOS/OnePass" -ApplePersistenceIgnoreState YES -AppleLanguages "(en)" -AppleLocale en_US \
  -NSRequiresAquaSystemAppearance YES -OnePassDemoData YES "$@" >/dev/null 2>&1 &
PID=$!
sleep "$WAIT"
$D/wl | awk -v p=$PID '$2==p' >&2
WID=$($D/wl | awk -v p=$PID '$2==p && $3==0 {print $4*$5, $1}' | sort -rn | head -1 | cut -d' ' -f2)
screencapture -x -o -l "$WID" "$OUT/mac-$NAME.png"
kill $PID 2>/dev/null
echo "$OUT/mac-$NAME.png $WID"
