#!/usr/bin/env bash
# Generates OnePassAppStore.xcodeproj next to OnePass.xcodeproj: the same app, for the Mac App
# Store. The store refuses any executable that is not sandboxed, so this project
#   - does not link UpdateKit (Sparkle): the store updates the app,
#   - does not embed or define OnePass Fill (Contents/Library/LoginItems), which cannot be sandboxed,
#   - does not define FillLab, the Debug-only test app of OnePass Fill, nor its scheme,
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

# OnePass Fill, the login item: not sandboxed, so never embedded in the store app.
fill = (
    "      - target: OnePassFill\n"
    "        destinationFilters: [macOS]\n"
    "        embed: true\n"
    "        copy:\n"
    "          destination: wrapper\n"
    "          subpath: Contents/Library/LoginItems\n"
)
assert fill in spec, "OnePassFill dependency not found in project.yml"
spec = spec.replace(fill, "", 1)

# Its target definition too, with the comment above it: the store project lists no helper at all.
target = re.compile(r"(?:^  #.*\n)*^  OnePassFill:\n(?:^(?:    .*)?\n)*", re.M)
assert len(target.findall(spec)) == 1, "OnePassFill target not found once in project.yml"
spec = target.sub("", spec, count=1)
assert "OnePassFill" not in spec, "OnePassFill still named in the App Store spec"

# FillLab, the Debug-only test app of OnePass Fill: the Mac UI tests' dependency on it, its target
# and its scheme (both blocks are `  FillLab:` with their comment), so the store project has none.
lab_dep = (
    "      # The hostile fields of FillAnywhereUITests, built next to the runner, not embedded.\n"
    "      - target: FillLab\n"
    "        embed: false\n"
)
assert lab_dep in spec, "FillLab dependency not found in project.yml"
spec = spec.replace(lab_dep, "", 1)
lab = re.compile(r"(?:^  #.*\n)*^  FillLab:\n(?:^(?:    .*)?\n)*", re.M)
assert len(lab.findall(spec)) == 2, "FillLab target and scheme not found once each in project.yml"
spec = lab.sub("", spec)
assert "FillLab" not in spec, "FillLab still named in the App Store spec"

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
