#!/usr/bin/env bash
# Builds OnePass for the founder's iPhone with ONE fixed personal signing identity, checks the
# signature of every bundle, then installs it with devicectl.
#
# Why the identity never changes: the Face ID enrollment (a Secure Enclave key and the wrapped
# AUK) and the Secret Key live in the keychain under the app's team, bundle id and keychain group.
# An install signed with another team or bundle id is another app to iOS: it cannot read them, and
# OnePass asks for the master password (and the Emergency Kit) again. Every value below must stay
# the same from one install to the next.
#
#   apple/scripts/install-iphone.sh [--dry-run] [--device <identifier, UDID or name>]
#   make -C apple install-iphone [ARGS="--dry-run"]
#
# --dry-run builds and checks, installs nothing. Without --device, the script picks the single
# paired, physical iPhone; it refuses when there are several, and it never picks a device named
# after someone else (a name with a possessive or "iPhone<Name>" must contain OWNER_NAME).
set -euo pipefail

# ---- Personal identity (one block, never edited between installs) ------------------------------
TEAM_ID="${ONEPASS_TEAM_ID:?set ONEPASS_TEAM_ID to your Apple team ID}"
BUNDLE_ID_PREFIX="me.quentincaron.onepass"
APP_GROUP="group.me.quentincaron.onepass"
CLOUDKIT_CONTAINER="iCloud.me.quentincaron.onepass"
# The user's items live in this keychain group: never change it.
KEYCHAIN_GROUP="me.somalabs.onepass.shared"
CONFIGURATION="Release-CloudKit"
OWNER_NAME="Quentin"
# The App ID of the notifications extension has no App Group (nor Time Sensitive Notifications)
# attached on the personal team, so that extension is signed without them: its alert then omits the
# Mac's name and may not break through a Focus. Once both are ticked on developer.apple.com, set
# these to the shipped file (which carries the group and the time-sensitive key) and "$APP_GROUP".
NOTIFICATIONS_ENTITLEMENTS="NotificationService/OnePassNotifications-NoGroup.entitlements"
NOTIFICATIONS_GROUP="-"
# --------------------------------------------------------------------------------------------------

APPLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DERIVED="$APPLE_DIR/DerivedData-install-iphone"
APP="$DERIVED/Build/Products/$CONFIGURATION-iphoneos/OnePass.app"

dry_run=0
device=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    --device) shift; device="${1:-}"; [ -n "$device" ] || { echo "error: --device needs a value" >&2; exit 2; } ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "error: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

fail() { echo "error: $*" >&2; exit 1; }

# ---- Device (chosen before the build, so a wrong pick costs nothing) -----------------------------
pick_device() {
  local json
  json="$(mktemp -t onepass-devices)"
  xcrun devicectl list devices --json-output "$json" >/dev/null 2>&1 || fail "devicectl cannot list devices"
  local status=0
  python3 -I - "$json" "$device" "$OWNER_NAME" <<'PY' || status=$?
import json, re, sys
path, wanted, owner = sys.argv[1], sys.argv[2], sys.argv[3]
devices = json.load(open(path))["result"]["devices"]
phones = []
for d in devices:
    hw, props, conn = d.get("hardwareProperties", {}), d.get("deviceProperties", {}), d.get("connectionProperties", {})
    if hw.get("reality") != "physical" or hw.get("deviceType") != "iPhone" or conn.get("pairingState") != "paired":
        continue
    phones.append((d.get("identifier", ""), hw.get("udid", ""), props.get("name", ""), conn.get("tunnelState", "")))

def someone_else(name):
    # "Chloe's iPhone", "iPhone de Chloe", "iPhoneChloe": a person's name that is not the owner's.
    personal = re.search(r"['’]s\b|\biPhone de\b|^iPhone[A-Z]", name)
    return bool(personal) and owner.lower() not in name.lower()

if wanted:
    match = [p for p in phones if wanted in (p[0], p[1], p[2])]
    if len(match) != 1:
        sys.exit(f"error: no single paired physical iPhone matches {wanted!r}")
    if someone_else(match[0][2]):
        sys.exit(f"error: {match[0][2]!r} looks like someone else's iPhone: refused")
    print(match[0][0]); sys.exit(0)
mine = [p for p in phones if not someone_else(p[2]) and p[3] != "unavailable"]
if len(mine) != 1:
    listed = ", ".join(f"{p[2]} ({p[0]})" for p in phones) or "none"
    sys.exit(f"error: {len(mine)} candidate iPhones, pass --device <identifier>. Paired physical iPhones: {listed}")
print(mine[0][0])
PY
  rm -f "$json"
  return $status
}

device_id=""
if [ $dry_run -eq 0 ]; then
  device_id="$(pick_device)" || exit 1
  echo "device: $device_id"
fi

# ---- Build ---------------------------------------------------------------------------------------
make -C "$APPLE_DIR" core
cd "$APPLE_DIR"
xcodebuild -project OnePass.xcodeproj -scheme OnePass -configuration "$CONFIGURATION" \
  -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED" -allowProvisioningUpdates \
  CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$TEAM_ID" \
  ONEPASS_BUNDLE_ID_PREFIX="$BUNDLE_ID_PREFIX" ONEPASS_APP_GROUP="$APP_GROUP" \
  ONEPASS_CLOUDKIT_CONTAINER="$CLOUDKIT_CONTAINER" ONEPASS_KEYCHAIN_GROUP="$KEYCHAIN_GROUP" \
  ONEPASS_NOTIFICATIONS_ENTITLEMENTS="$NOTIFICATIONS_ENTITLEMENTS" \
  build
[ -d "$APP" ] || fail "built app not found at $APP"

# ---- Verify every signed bundle ------------------------------------------------------------------
verify() {
  local bundle=$1 bundle_id=$2 keychain=$3 group=$4 container=$5
  local ents info
  ents="$(mktemp -t onepass-ents)"
  info="$bundle/Info.plist"
  codesign --verify --strict "$bundle" || fail "$bundle: signature does not verify"
  codesign -d --entitlements - --xml "$bundle" >"$ents" 2>/dev/null || fail "$bundle: no entitlements"
  python3 -I - "$ents" "$info" "$TEAM_ID" "$bundle_id" "$keychain" "$group" "$container" <<'PY' || { rm -f "$ents"; fail "$bundle: identity mismatch"; }
import plistlib, sys
ents_path, info_path, team, bundle_id, keychain, group, container = sys.argv[1:]
ents = plistlib.load(open(ents_path, "rb"))
info = plistlib.load(open(info_path, "rb"))
errors = []
def same(label, got, want):
    if got != want:
        errors.append(f"{label}: {got!r}, expected {want!r}")
same("CFBundleIdentifier", info.get("CFBundleIdentifier"), bundle_id)
same("application-identifier", ents.get("application-identifier"), f"{team}.{bundle_id}")
same("team-identifier", ents.get("com.apple.developer.team-identifier"), team)
if keychain != "-":
    same("keychain-access-groups", ents.get("keychain-access-groups"), [f"{team}.{keychain}"])
if group != "-":
    same("application-groups", ents.get("com.apple.security.application-groups"), [group])
if container != "-":
    same("icloud-container-identifiers", ents.get("com.apple.developer.icloud-container-identifiers"), [container])
if keychain != "-":
    same("Info.plist OnePassKeychainGroup", info.get("OnePassKeychainGroup"), keychain)
if group != "-":
    same("Info.plist OnePassAppGroup", info.get("OnePassAppGroup"), group)
for e in errors:
    print("  " + e, file=sys.stderr)
sys.exit(1 if errors else 0)
PY
  rm -f "$ents"
  echo "ok: ${bundle#"$DERIVED"/}"
}

verify "$APP" "$BUNDLE_ID_PREFIX" "$KEYCHAIN_GROUP" "$APP_GROUP" "$CLOUDKIT_CONTAINER"
verify "$APP/PlugIns/OnePassAutoFill.appex" "$BUNDLE_ID_PREFIX.autofill" "$KEYCHAIN_GROUP" "$APP_GROUP" -
verify "$APP/PlugIns/OnePassWidgets.appex" "$BUNDLE_ID_PREFIX.widgets" - "$APP_GROUP" -
verify "$APP/PlugIns/OnePassNotifications.appex" "$BUNDLE_ID_PREFIX.notifications" - "$NOTIFICATIONS_GROUP" -
WATCH="$APP/Watch/OnePassWatch.app"
if [ -d "$WATCH" ]; then
  verify "$WATCH" "$BUNDLE_ID_PREFIX.watchkitapp" - - -
  companion=$(plutil -extract WKCompanionAppBundleIdentifier raw "$WATCH/Info.plist")
  [ "$companion" = "$BUNDLE_ID_PREFIX" ] || fail "watch companion is $companion, expected $BUNDLE_ID_PREFIX"
  verify "$WATCH/PlugIns/OnePassWatchWidgets.appex" "$BUNDLE_ID_PREFIX.watchkitapp.widgets" - - -
fi

if [ $dry_run -eq 1 ]; then
  echo "dry run: built and verified $APP, nothing installed"
  exit 0
fi

# ---- Install -------------------------------------------------------------------------------------
xcrun devicectl device install app --device "$device_id" "$APP"
echo "installed $BUNDLE_ID_PREFIX (team $TEAM_ID) on $device_id"
