#!/usr/bin/env bash
# Refresh the embedded data from Apple's password-manager-resources (MIT):
# the site password rules and the domains that share their credentials.
# Usage: update-password-quirks.sh [rules-sha [shared-sha]]
# One commit given: both files move to it. None: each stays at its pin.
# Pinned commit of quirks/password-rules.json (default):
PINNED_SHA="ab0a64ee50eaa78a4ea7c86a291594860f26d18f"
# Pinned commit of quirks/shared-credentials.json (default), also recorded
# next to the file in data/SHARED_CREDENTIALS_COMMIT:
SHARED_PINNED_SHA="316412ba01dba1d84dc52d51267f503964638e20"
set -euo pipefail

sha="${1:-$PINNED_SHA}"
shared_sha="${2:-${1:-$SHARED_PINNED_SHA}}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/core/onepass-bridge/data"
repo="https://raw.githubusercontent.com/apple/password-manager-resources"
base="$repo/$sha"
shared_base="$repo/$shared_sha"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$base/quirks/password-rules.json" -o "$tmp/password-rules.json"
curl -fsSL "$base/LICENSE.md" -o "$tmp/LICENSE"
jq empty "$tmp/password-rules.json"
test -s "$tmp/LICENSE"

curl -fsSL "$shared_base/quirks/shared-credentials.json" -o "$tmp/shared-credentials.json"
curl -fsSL "$shared_base/LICENSE.md" -o "$tmp/SHARED_LICENSE"
# A list of groups, each `shared` or `from` and `to`: what the core parses.
jq -e 'type == "array" and length > 0
       and all(.[]; type == "object" and (has("shared") or (has("from") and has("to"))))' \
  "$tmp/shared-credentials.json" >/dev/null
test -s "$tmp/SHARED_LICENSE"

mkdir -p "$out"
cp "$tmp/password-rules.json" "$out/password-rules.json"
cp "$tmp/LICENSE" "$out/PASSWORD_RULES_LICENSE"
cp "$tmp/shared-credentials.json" "$out/shared-credentials.json"
cp "$tmp/SHARED_LICENSE" "$out/SHARED_CREDENTIALS_LICENSE"
echo "$shared_sha" > "$out/SHARED_CREDENTIALS_COMMIT"
echo "$sha"
echo "$shared_sha"
