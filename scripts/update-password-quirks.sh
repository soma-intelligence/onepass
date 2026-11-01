#!/usr/bin/env bash
# Refresh the embedded site password rules from Apple's
# password-manager-resources (MIT). Usage: update-password-quirks.sh [commit-sha]
# Pinned commit (default):
PINNED_SHA="ab0a64ee50eaa78a4ea7c86a291594860f26d18f"
set -euo pipefail

sha="${1:-$PINNED_SHA}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/core/onepass-bridge/data"
base="https://raw.githubusercontent.com/apple/password-manager-resources/$sha"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$base/quirks/password-rules.json" -o "$tmp/password-rules.json"
curl -fsSL "$base/LICENSE.md" -o "$tmp/LICENSE"
jq empty "$tmp/password-rules.json"
test -s "$tmp/LICENSE"

mkdir -p "$out"
cp "$tmp/password-rules.json" "$out/password-rules.json"
cp "$tmp/LICENSE" "$out/PASSWORD_RULES_LICENSE"
echo "$sha"
