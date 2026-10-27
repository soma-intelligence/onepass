#!/usr/bin/env bash
# Fails if a GitHub Actions `uses:` reference is not pinned to a full commit
# SHA (@ followed by 40 hex characters). Local actions (./path) are exempt.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0

shopt -s nullglob
files=("$root"/.github/workflows/*.yml "$root"/.github/workflows/*.yaml "$root"/.github/actions/*/action.yml)

for f in "${files[@]}"; do
  while IFS= read -r line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["'\'']//; s/["'\'']$//')"
    case "$ref" in
      ./*) continue ;;
    esac
    if ! printf '%s' "$ref" | grep -Eq '@[0-9a-f]{40}$'; then
      echo "not pinned to a commit SHA: ${f#"$root"/}: $ref" >&2
      status=1
    fi
  done < <(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$f" || true)
done

if [ "$status" -eq 0 ]; then
  echo "all actions are pinned to a commit SHA"
fi
exit "$status"
