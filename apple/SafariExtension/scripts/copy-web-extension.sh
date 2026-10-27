#!/usr/bin/env bash
# Xcode build phase of OnePassSafari: copies the built web extension
# (extension/dist/safari, from `cd extension && npm run build`) into the
# appex's Resources, where Safari looks for manifest.json.
set -euo pipefail

SRC="${PROJECT_DIR}/../extension/dist/safari"
DEST="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}"

if [ ! -f "$SRC/manifest.json" ]; then
  echo "error: $SRC/manifest.json is missing. Build the extension first: cd extension && npm ci && npm run build" >&2
  exit 1
fi

mkdir -p "$DEST"
cp -R "$SRC/." "$DEST/"
