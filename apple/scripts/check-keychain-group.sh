#!/usr/bin/env bash
# Xcode build phase of OnePass, run before its sources (also runnable by hand):
# fails the build when an entitlements file names a keychain access group
# other than the build setting, `$(AppIdentifierPrefix)$(ONEPASS_KEYCHAIN_GROUP)`.
#
# The code reads the group from the `OnePassKeychainGroup` Info.plist key,
# set to the same `$(ONEPASS_KEYCHAIN_GROUP)`. A build whose entitlements say
# one group while the code asks for another gets errSecMissingEntitlement
# (-34018) at unlock: change the group with the build setting
# (apple/project.yml, or a configuration override), never in an
# entitlements file. VaultKit's KeychainGroupSettingTests checks the same.
set -euo pipefail

APPLE_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
EXPECTED='$(AppIdentifierPrefix)$(ONEPASS_KEYCHAIN_GROUP)'
status=0

while IFS= read -r -d '' file; do
  groups=$(plutil -extract keychain-access-groups json -o - "$file" 2>/dev/null) || continue
  if [ "$groups" != "[\"$EXPECTED\"]" ]; then
    echo "error: ${file#"$APPLE_DIR"/}: keychain-access-groups is $groups, expected [\"$EXPECTED\"]." \
      "Change the group with the ONEPASS_KEYCHAIN_GROUP build setting (apple/project.yml), never in an entitlements file." >&2
    status=1
  fi
done < <(find "$APPLE_DIR" \( -name 'DerivedData*' -o -name build -o -name .build -o -name node_modules \) -prune \
  -o -name '*.entitlements' -print0)

exit $status
