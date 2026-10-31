#!/usr/bin/env bash
# Xcode build phase of OnePass, run before its sources (also runnable by hand):
# fails the build when an entitlements file names a keychain access group or
# an App Group other than the build settings:
#   keychain-access-groups              = $(AppIdentifierPrefix)$(ONEPASS_KEYCHAIN_GROUP)
#   com.apple.security.application-groups = $(ONEPASS_APP_GROUP)
#
# The code reads both from Info.plist keys set to the same settings
# (`OnePassKeychainGroup`, `OnePassAppGroup`). A build whose entitlements say
# one group while the code asks for another gets errSecMissingEntitlement
# (-34018) at unlock, or widgets that read an empty container: change a group
# with its build setting (apple/project.yml, or a command line override as
# scripts/install-iphone.sh does), never in an entitlements file. VaultKit's
# KeychainGroupSettingTests checks the same.
set -euo pipefail

APPLE_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
status=0

check() {
  local file=$1 key=$2 expected=$3 value
  value=$(plutil -extract "$key" json -o - "$file" 2>/dev/null) || return 0
  if [ "$value" != "[\"$expected\"]" ]; then
    echo "error: ${file#"$APPLE_DIR"/}: ${key//\\/} is $value, expected [\"$expected\"]." \
      "Change the group with its build setting (apple/project.yml), never in an entitlements file." >&2
    status=1
  fi
}

while IFS= read -r -d '' file; do
  check "$file" keychain-access-groups '$(AppIdentifierPrefix)$(ONEPASS_KEYCHAIN_GROUP)'
  check "$file" 'com\.apple\.security\.application-groups' '$(ONEPASS_APP_GROUP)'
done < <(find "$APPLE_DIR" \( -name 'DerivedData*' -o -name build -o -name .build -o -name node_modules \) -prune \
  -o -name '*.entitlements' -print0)

exit $status
