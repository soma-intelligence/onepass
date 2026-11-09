#!/usr/bin/env bash
# Checks only what a change touches, then prints one summary table.
#
#   scripts/verify.sh                 changes since origin/main (merge base),
#                                     committed or not, untracked files too
#   scripts/verify.sh --base <ref>    changes since <ref> instead
#   scripts/verify.sh --all           everything: release-grade full run
#   scripts/verify.sh --apple         add the Apple steps even when neither
#                                     apple/ nor onepass-ffi changed
#   scripts/verify.sh --dry-run       print the plan, run nothing
#   scripts/verify.sh --no-queue      skip the machine-wide build queue
#                                     (same as ONEPASS_NO_QUEUE=1)
#
# What runs for which change:
# - core/<crate>/: cargo nextest (profile verify) for that crate and every
#   workspace crate that depends on it (cargo metadata). onepass-core, a root
#   manifest, Cargo.lock, rust-toolchain.toml or core/.cargo, core/.config:
#   the whole workspace. A change under a crate's src/ adds its doctests
#   (`cargo test --doc`, which nextest does not run).
# - extension/: tsc, vitest (`vitest related` on the changed files when they
#   all sit under extension/src, the whole suite otherwise) and the build.
# - apple/<package>/ (VaultKit, DesignKit, CompanionKit, UpdateKit): that
#   package's swift tests, and those of the packages that depend on it.
#   Tests tagged `.slow` run alone and serially after the parallel run.
# - apple/ outside package tests, onepass-ffi or build-core.sh: the core
#   XCFramework (dev) and xcodebuild for the iOS Simulator and macOS.
# - android/: the Gradle checks of CI when a JDK and an Android SDK exist,
#   skipped with a note otherwise.
# - scripts/*.sh: bash -n and shellcheck. Strings: the i18n check.
#
# Heavy steps (cargo, build-core.sh, swift test, xcodebuild, Gradle) go
# through scripts/heavy.sh, one at a time on this Mac. Every step's output is
# in a log file; a failed step prints its last lines. Exits non-zero when a
# step fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/scripts/verify.sh"
HEAVY="$ROOT/scripts/heavy.sh"

# Internal: run a cargo command after claiming a shared target directory.
# Runs inside heavy.sh, so no other queued build uses the directory.
if [ "${1:-}" = __claim-target ]; then
  shift
  marker="$CARGO_TARGET_DIR/.onepass-checkout"
  if [ -d "$CARGO_TARGET_DIR" ] && [ "$(cat "$marker" 2>/dev/null || true)" != "$ROOT" ]; then
    echo "verify: $CARGO_TARGET_DIR was last used by another checkout: removing the workspace crates' artifacts"
    members=()
    while IFS= read -r m; do members+=(-p "$m"); done < <(
      cd "$ROOT/core" && cargo metadata --format-version 1 --no-deps --offline | jq -r '.packages[].name')
    (cd "$ROOT/core" && cargo clean "${members[@]}")
  fi
  mkdir -p "$CARGO_TARGET_DIR"
  echo "$ROOT" > "$marker"
  exec "$@"
fi

BASE="origin/main"
ALL=0
DRY=0
FORCE_APPLE=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base) BASE="${2:?--base needs a ref}"; shift 2 ;;
    --base=*) BASE="${1#--base=}"; shift ;;
    --all) ALL=1; shift ;;
    --apple) FORCE_APPLE=1; shift ;;
    --dry-run | -n) DRY=1; shift ;;
    --no-queue) export ONEPASS_NO_QUEUE=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "verify: unknown argument $1 (see --help)" >&2; exit 64 ;;
  esac
done

cd "$ROOT"

# ---------------------------------------------------------------- the change
CHANGED=()
if [ "$ALL" = 0 ]; then
  merge_base="$(git merge-base "$BASE" HEAD)" || { echo "verify: no merge base with $BASE" >&2; exit 64; }
  while IFS= read -r f; do CHANGED+=("$f"); done < <(
    { git diff --name-only "$merge_base"; git ls-files --others --exclude-standard; } | sort -u)
fi

RUST_ALL=$ALL
RUST_DIRECT=()   # crates changed directly
DOC_CRATES=()    # crates whose src/ changed
EXT=$ALL
EXT_FULL=$ALL
EXT_FILES=()
SWIFT_PKGS=()
APP=$((ALL || FORCE_APPLE))
FFI=$((ALL || FORCE_APPLE))
ANDROID=$ALL
I18N=$ALL
SHELL_FILES=()
NOTES=()

has() { local x="$1"; shift; for y in "$@"; do [ "$x" = "$y" ] && return 0; done; return 1; }
# add ARRAY VALUE: appends VALUE to the array named ARRAY unless it is there.
add() { eval "has \"\$2\" \${${1}[@]+\"\${${1}[@]}\"}" || eval "${1}+=(\"\$2\")"; }

for f in ${CHANGED[@]+"${CHANGED[@]}"}; do
  case "$f" in
    core/fuzz/*) NOTES+=("$f: fuzz targets are not run here (make -C core fuzz)") ;;
    core/onepass-*/*)
      crate="${f#core/}"; crate="${crate%%/*}"
      add RUST_DIRECT "$crate"
      [[ "$f" == "core/$crate/src/"* ]] && add DOC_CRATES "$crate"
      [ "$crate" = onepass-ffi ] && FFI=1 ;;
    core/Cargo.toml | core/Cargo.lock | core/rust-toolchain.toml | core/.cargo/* | core/.config/*)
      RUST_ALL=1; FFI=1 ;;
    core/*) NOTES+=("$f: no check mapped") ;;
    extension/src/*) EXT=1; add EXT_FILES "${f#extension/}" ;;
    extension/*.md) NOTES+=("$f: no check mapped") ;;
    extension/*) EXT=1; EXT_FULL=1 ;;
    apple/scripts/build-core.sh) FFI=1 ;;
    apple/VaultKit/* | apple/DesignKit/* | apple/CompanionKit/* | apple/UpdateKit/*)
      pkg="${f#apple/}"; pkg="${pkg%%/*}"
      add SWIFT_PKGS "$pkg"
      [[ "$f" == "apple/$pkg/Tests/"* ]] || APP=1
      [[ "$f" == *.xcstrings ]] && I18N=1 ;;
    apple/*.md) NOTES+=("$f: no check mapped") ;;
    apple/*) APP=1; [[ "$f" == *.xcstrings ]] && I18N=1 ;;
    android/*) ANDROID=1 ;;
    scripts/i18n/*) I18N=1 ;;
    *.sh) ;;
    *) NOTES+=("$f: no check mapped") ;;
  esac
  [[ "$f" == *.sh ]] && add SHELL_FILES "$f"
done

# A change of the FFI or its build reaches every package linking the core,
# and the apps.
if [ "$FFI" = 1 ]; then APP=1; add SWIFT_PKGS VaultKit; fi
# DesignKit and CompanionKit depend on VaultKit.
if has VaultKit ${SWIFT_PKGS[@]+"${SWIFT_PKGS[@]}"}; then add SWIFT_PKGS DesignKit; add SWIFT_PKGS CompanionKit; fi
if [ "$ALL" = 1 ]; then for p in VaultKit DesignKit CompanionKit UpdateKit; do add SWIFT_PKGS "$p"; done; fi

# ---------------------------------------------------------- the Rust crates
META="$(cd core && cargo metadata --format-version 1 --no-deps --offline 2>/dev/null)" \
  || META="$(cd core && cargo metadata --format-version 1 --no-deps)"
# "dependency consumer" pairs inside the workspace (normal, dev and build).
EDGES="$(jq -r '.packages[] | .name as $n | .dependencies[] | select(.path) | "\(.name) \($n)"' <<<"$META" | sort -u)"
LIB_CRATES="$(jq -r '.packages[] | select(any(.targets[]; any(.kind[]; . == "lib" or . == "rlib"))) | .name' <<<"$META")"

rdeps_closure() {
  local queue=("$@") seen=("$@") c d
  while [ "${#queue[@]}" -gt 0 ]; do
    c="${queue[0]}"; queue=("${queue[@]:1}")
    while read -r d; do
      [ -n "$d" ] || continue
      has "$d" "${seen[@]}" || { seen+=("$d"); queue+=("$d"); }
    done < <(awk -v c="$c" '$1 == c { print $2 }' <<<"$EDGES")
  done
  printf '%s\n' "${seen[@]}" | sort -u
}

RUST_CRATES=()
if has onepass-core ${RUST_DIRECT[@]+"${RUST_DIRECT[@]}"}; then RUST_ALL=1; fi
if [ "$RUST_ALL" = 0 ] && [ "${#RUST_DIRECT[@]}" -gt 0 ]; then
  while read -r c; do RUST_CRATES+=("$c"); done < <(rdeps_closure "${RUST_DIRECT[@]}")
  has onepass-core "${RUST_CRATES[@]}" && RUST_ALL=1
fi

NEEDS_FAST_KDF=$RUST_ALL
if [ "$RUST_ALL" = 0 ] && [ "${#RUST_CRATES[@]}" -gt 0 ]; then
  core_users="$(rdeps_closure onepass-core)"
  for c in "${RUST_CRATES[@]}"; do grep -qx "$c" <<<"$core_users" && NEEDS_FAST_KDF=1; done
fi

# ------------------------------------------------------------------ the plan
S_NAME=(); S_DIR=(); S_CMD=(); S_HEAVY=(); S_NEEDS=()
step() { # name dir heavy needs cmd...
  S_NAME+=("$1"); S_DIR+=("$2"); S_HEAVY+=("$3"); S_NEEDS+=("$4"); shift 4
  S_CMD+=("$(printf '%q ' "$@")")
}

if [ "${#SHELL_FILES[@]}" -gt 0 ]; then
  existing=(); for f in "${SHELL_FILES[@]}"; do [ -f "$f" ] && existing+=("$f"); done
  if [ "${#existing[@]}" -gt 0 ]; then
    # shellcheck disable=SC2016 # expanded by the inner bash
    step "shell syntax" . 0 - bash -c 'for f in "$@"; do bash -n "$f" || exit 1; done' _ "${existing[@]}"
    command -v shellcheck >/dev/null && step "shellcheck" . 0 - shellcheck -x "${existing[@]}"
  fi
fi

if [ "$RUST_ALL" = 1 ] || [ "${#RUST_CRATES[@]}" -gt 0 ]; then
  sel=(--workspace)
  if [ "$RUST_ALL" = 0 ]; then sel=(); for c in "${RUST_CRATES[@]}"; do sel+=(-p "$c"); done; fi
  feat=(); [ "$NEEDS_FAST_KDF" = 1 ] && feat=(--features onepass-core/dev-fast-kdf)
  claim=(); [ -n "${CARGO_TARGET_DIR:-}" ] && claim=("$SELF" __claim-target)
  step "rust nextest" core 1 - ${claim[@]+"${claim[@]}"} cargo nextest run --profile verify "${sel[@]}" ${feat[@]+"${feat[@]}"}
  doc=()
  if [ "$ALL" = 1 ] || { [ "$RUST_ALL" = 1 ] && [ "${#DOC_CRATES[@]}" -gt 0 ]; }; then
    doc=(--workspace)
  elif [ "${#DOC_CRATES[@]}" -gt 0 ]; then
    for c in "${RUST_CRATES[@]}"; do grep -qx "$c" <<<"$LIB_CRATES" && doc+=(-p "$c"); done
  fi
  [ "${#doc[@]}" -gt 0 ] && step "rust doctests" core 1 - ${claim[@]+"${claim[@]}"} cargo test --doc "${doc[@]}" ${feat[@]+"${feat[@]}"}
fi

if [ "$EXT" = 1 ]; then
  ext_needs=-
  if [ ! -d extension/node_modules ]; then step "extension npm ci" extension 0 - npm ci --no-audit --no-fund; ext_needs="extension npm ci"; fi
  step "extension tsc" extension 0 "$ext_needs" npx tsc --noEmit
  related=(); for f in ${EXT_FILES[@]+"${EXT_FILES[@]}"}; do [ -f "extension/$f" ] && related+=("$f"); done
  if [ "$EXT_FULL" = 0 ] && [ "${#related[@]}" -gt 0 ]; then
    step "extension vitest related" extension 0 "$ext_needs" npx vitest related --run "${related[@]}"
  else
    step "extension vitest" extension 0 "$ext_needs" npx vitest run
  fi
  step "extension build" extension 0 "$ext_needs" npm run build
fi

FFI_TEST=../build/test/OnePassFFI.xcframework  # relative to apple/VaultKit
needs_ffi=0
for p in ${SWIFT_PKGS[@]+"${SWIFT_PKGS[@]}"}; do [ "$p" != UpdateKit ] && needs_ffi=1; done
[ "$needs_ffi" = 1 ] && step "core xcframework (test)" . 1 - apple/scripts/build-core.sh test

# Test IDs (swift-testing --filter/--skip regex) of the tests tagged .slow.
slow_regex() {
  awk '
    /@Suite\(.*\.slow/ { want = 1 }
    want && match($0, /(struct|class|actor|enum) [A-Za-z0-9_]+/) {
      s = substr($0, RSTART, RLENGTH); sub(/^[a-z]+ /, "", s); print "\\." s "/"; want = 0; next }
    /@Test\(.*\.slow/ && match($0, /func [A-Za-z0-9_]+/) { print "/" substr($0, RSTART + 5, RLENGTH - 5) "\\(" }
  ' "$1"/Tests/*/*.swift 2>/dev/null | sort -u | paste -sd'|' -
}

for p in VaultKit DesignKit CompanionKit UpdateKit; do
  has "$p" ${SWIFT_PKGS[@]+"${SWIFT_PKGS[@]}"} || continue
  envs=(); needs=-
  [ "$p" != UpdateKit ] && { envs=(env ONEPASS_FFI_XCFRAMEWORK="$FFI_TEST"); needs="core xcframework (test)"; }
  slow="$(slow_regex "apple/$p")"
  if [ -n "$slow" ]; then
    step "swift $p (parallel)" . 1 "$needs" ${envs[@]+"${envs[@]}"} swift test --package-path "apple/$p" --skip "$slow"
    step "swift $p (.slow, serial)" . 1 "swift $p (parallel)" ${envs[@]+"${envs[@]}"} \
      swift test --package-path "apple/$p" --skip-build --no-parallel --filter "$slow"
  else
    step "swift $p" . 1 "$needs" ${envs[@]+"${envs[@]}"} swift test --package-path "apple/$p"
  fi
done

if [ "$APP" = 1 ]; then
  step "core xcframework (dev)" . 1 - apple/scripts/build-core.sh dev
  for dest in ios mac; do
    if [ "${ONEPASS_SHARED_DERIVED:-0}" = 1 ]; then
      dd="$HOME/Library/Caches/onepass-derived/OnePass-$dest"
    else
      dd="$ROOT/apple/DerivedData"
    fi
    if [ "$dest" = ios ]; then
      d=(-destination 'generic/platform=iOS Simulator' ARCHS=arm64 ONLY_ACTIVE_ARCH=YES)
    else
      d=(-destination 'platform=macOS,arch=arm64')
    fi
    step "xcodebuild $dest" apple 1 "core xcframework (dev)" xcodebuild -quiet -project OnePass.xcodeproj \
      -scheme OnePass -configuration Debug "${d[@]}" -derivedDataPath "$dd" CODE_SIGNING_ALLOWED=NO build
  done
fi

ANDROID_NOTE=""
if [ "$ANDROID" = 1 ]; then
  sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  if ! /usr/libexec/java_home >/dev/null 2>&1 && [ -z "${JAVA_HOME:-}" ]; then
    ANDROID_NOTE="android: skipped, no JDK (/usr/libexec/java_home finds none, JAVA_HOME unset)"
  elif [ ! -d "$sdk/platforms" ]; then
    ANDROID_NOTE="android: skipped, no Android SDK platforms in $sdk (set ANDROID_HOME)"
  elif ! cargo ndk --version >/dev/null 2>&1; then
    ANDROID_NOTE="android: skipped, cargo-ndk is not installed (android/scripts/versions.env)"
  else
    step "android gradle" android 1 - env ANDROID_HOME="$sdk" ./gradlew testPlayDebugUnitTest testFdroidDebugUnitTest lintPlayDebug assemblePlayDebug
  fi
fi

[ "$I18N" = 1 ] && step "i18n check" . 0 - python3 -I scripts/i18n/i18n.py check

# ------------------------------------------------------------- dry run
if [ "$ALL" = 1 ]; then scope="everything (--all)"; else scope="${#CHANGED[@]} files changed since $BASE (merge base ${merge_base:0:8})"; fi
echo "verify: $scope"
if [ "$RUST_ALL" = 1 ]; then echo "  rust: whole workspace"
elif [ "${#RUST_CRATES[@]}" -gt 0 ]; then echo "  rust: ${RUST_CRATES[*]} (changed: ${RUST_DIRECT[*]})"; fi
[ "${#SWIFT_PKGS[@]}" -gt 0 ] && echo "  swift packages: ${SWIFT_PKGS[*]}"
[ -n "$ANDROID_NOTE" ] && echo "  $ANDROID_NOTE"
for n in ${NOTES[@]+"${NOTES[@]}"}; do echo "  note: $n"; done

if [ "${#S_NAME[@]}" -eq 0 ]; then echo "verify: nothing to check"; exit 0; fi

if [ "$DRY" = 1 ]; then
  echo "plan:"
  for i in "${!S_NAME[@]}"; do
    q=""; [ "${S_HEAVY[$i]}" = 1 ] && q="[queued] "
    printf '  %2d. %-28s %s(in %s) %s\n' "$((i + 1))" "${S_NAME[$i]}" "$q" "${S_DIR[$i]}" "${S_CMD[$i]}"
  done
  exit 0
fi

# ------------------------------------------------------------------ the run
# shellcheck source=scripts/dev-env.sh
. "$ROOT/scripts/dev-env.sh"
if [ -n "${CARGO_TARGET_DIR:-}" ] && [ "${ONEPASS_NO_QUEUE:-0}" = 1 ]; then
  echo "verify: a shared CARGO_TARGET_DIR needs the build queue; drop --no-queue or ONEPASS_SHARED_TARGET" >&2
  exit 64
fi

_tmp="${TMPDIR:-/tmp}"
LOG_DIR="${ONEPASS_VERIFY_LOGS:-${_tmp%/}/onepass-verify}/$(basename "$ROOT")-$(date '+%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"
R_RESULT=(); R_TIME=()
failed=0
started_all=$(date +%s)

for i in "${!S_NAME[@]}"; do
  name="${S_NAME[$i]}"
  needs="${S_NEEDS[$i]}"
  if [ "$needs" != - ]; then
    for j in "${!S_NAME[@]}"; do
      if [ "${S_NAME[$j]}" = "$needs" ] && [ "${R_RESULT[$j]:-}" != ok ]; then
        R_RESULT[i]="skip"; R_TIME[i]=0
        echo "verify: $name skipped ($needs did not pass)"
        continue 2
      fi
    done
  fi
  log="$LOG_DIR/$(printf '%02d' "$((i + 1))")-$(tr -c 'A-Za-z0-9.-' '_' <<<"$name" | sed 's/_*$//').log"
  cmd="${S_CMD[$i]}"
  [ "${S_HEAVY[$i]}" = 1 ] && cmd="$(printf '%q ' "$HEAVY")$cmd"
  echo "verify: $name"
  t0=$(date +%s)
  if (cd "$ROOT/${S_DIR[$i]}" && eval "$cmd") >"$log" 2>&1 </dev/null; then
    R_RESULT[i]=ok
  else
    R_RESULT[i]=FAIL; failed=1
    echo "---- $name failed, last lines of $log:"
    tail -n 40 "$log" | sed 's/^/  /'
    echo "----"
  fi
  R_TIME[i]=$(($(date +%s) - t0))
done

fmt() { printf '%dm%02ds' "$(($1 / 60))" "$(($1 % 60))"; }
echo
printf '%-30s %-6s %s\n' STEP RESULT TIME
for i in "${!S_NAME[@]}"; do
  printf '%-30s %-6s %s\n' "${S_NAME[$i]}" "${R_RESULT[$i]:-skip}" "$(fmt "${R_TIME[$i]:-0}")"
done
printf '%-30s %-6s %s\n' total "$([ "$failed" = 0 ] && echo ok || echo FAIL)" "$(fmt $(($(date +%s) - started_all)))"
[ -n "$ANDROID_NOTE" ] && echo "$ANDROID_NOTE"
echo "logs: $LOG_DIR"
exit "$failed"
