#!/usr/bin/env bash
# Generates OnePassAppStore.xcodeproj next to OnePass.xcodeproj: the same app, for the Mac App
# Store. The store refuses any executable that is not sandboxed, so this project
#   - does not link UpdateKit (Sparkle): the store updates the app,
#   - sets ONEPASS_APP_STORE (a Swift condition and a build setting): the code drops the updater,
#     the build phases leave out onepass-relay and onepass-mcp (Chrome, Firefox and MCP clients
#     then reach no app; Safari goes through its own extension).
# iOS, iPadOS, visionOS and watchOS builds are the same from either project. The generated project
# is not committed: run this before an App Store archive.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'EOF'
import re

spec = open("project.yml").read()

spec = spec.replace("name: OnePass\n", "name: OnePassAppStore\n", 1)

# The UpdateKit dependency of the app target, with its comment.
updater = (
    "      # Updates from GitHub Releases (Sparkle): the Developer ID Mac app only.\n"
    "      - package: UpdateKit\n"
    "        product: UpdateKit\n"
    "        destinationFilters: [macOS]\n"
)
assert updater in spec, "UpdateKit dependency not found in project.yml"
spec = spec.replace(updater, "", 1)

# The app target's settings: the first `settings:` / `base:` after `  OnePass:` / `type: application`.
start = spec.index("  OnePass:\n    type: application\n")
anchor = "    settings:\n      base:\n"
at = spec.index(anchor, start) + len(anchor)
spec = spec[:at] + (
    "        ONEPASS_APP_STORE: \"YES\"\n"
    "        SWIFT_ACTIVE_COMPILATION_CONDITIONS: \"$(inherited) ONEPASS_APP_STORE\"\n"
) + spec[at:]

# Release-CloudKit sets its own conditions per target, over the base ones: add the flag there too.
spec = spec.replace('"$(inherited) ONEPASS_CLOUDKIT"', '"$(inherited) ONEPASS_CLOUDKIT ONEPASS_APP_STORE"')

open("project-appstore.yml", "w").write(spec)
EOF

xcodegen generate --spec project-appstore.yml
rm -f project-appstore.yml
echo "OnePassAppStore.xcodeproj generated"
