# shellcheck shell=bash
# Source this file (`. scripts/dev-env.sh`) before building or testing in a
# checkout, especially when several checkouts build at the same time.
# scripts/verify.sh sources it for you.
#
# - sccache caches compiled crates by content in one shared directory
#   (~/Library/Caches/onepass-sccache), so a dependency (aws-lc, SQLite,
#   libcrux...) compiles once for every checkout. The server is started here
#   from a clean environment (scripts/sccache-start.sh), before any build
#   exports a deployment target.
# - Each checkout keeps its own core/target by default (CARGO_TARGET_DIR is
#   unset). ONEPASS_SHARED_TARGET=1 (or a directory) shares one target
#   directory between checkouts instead: see "Shared target directory" below.
# - Builds are capped at ONEPASS_JOBS jobs (default 4) and test runs at the
#   same number of threads.
# - ONEPASS_SHARED_DERIVED=1 makes scripts/verify.sh build with one Xcode
#   DerivedData per scheme and destination under
#   ~/Library/Caches/onepass-derived, shared by every checkout.

_onepass_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"

if command -v sccache >/dev/null 2>&1; then
  export RUSTC_WRAPPER=sccache
  export SCCACHE_DIR="${SCCACHE_DIR:-$HOME/Library/Caches/onepass-sccache}"
  export SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-40G}"
  # Rust compiles embed absolute paths: strip each checkout's root so a crate
  # built in one checkout is a cache hit in another (measured: 0% to 73%).
  # Every sibling checkout, sorted, so that all of them compute the same list
  # and share one server; scripts/sccache-start.sh restarts the server when
  # the list changes (a checkout was added) and nothing compiles.
  _onepass_roots=""
  for _d in "$(dirname "$_onepass_root")"/*/; do
    _d="${_d%/}"
    if [ -d "$_d/.git" ] || [ "$_d" = "$_onepass_root" ]; then
      _onepass_roots="$_onepass_roots${_onepass_roots:+:}$_d"
    fi
  done
  export SCCACHE_BASEDIRS="$_onepass_roots"
  "$_onepass_root/scripts/sccache-start.sh" || true
  unset _onepass_roots _d
else
  echo "dev-env: sccache not found (brew install sccache); building without a shared cache" >&2
fi

# Shared target directory. Off by default, because cargo is not safe with
# one target directory for two checkouts of the same workspace: both build
# their workspace crates under the same file names (the hashes do not depend
# on the checkout's path), and cargo decides freshness by modification time.
# Measured: after checkout B builds, checkout A, whose sources are older,
# runs B's test binary without rebuilding. Cargo's lock on the directory only
# stops two builds from writing at once (the second one waits on
# "Blocking waiting for file lock on build directory").
#
# scripts/verify.sh makes a shared directory safe: it runs every cargo step
# through the build queue (scripts/heavy.sh) and, when the directory was
# last used by another checkout, first removes the workspace crates' own
# artifacts (`cargo clean -p` for each member). Dependencies, the bulk of a
# build, are kept. Plain cargo commands in a shell with a shared directory
# get no such guard: prefer verify.sh there.
case "${ONEPASS_SHARED_TARGET:-}" in
  "" | 0 | no | false) unset CARGO_TARGET_DIR ;;
  1 | yes | true) export CARGO_TARGET_DIR="$HOME/Library/Caches/onepass-target" ;;
  *) export CARGO_TARGET_DIR="$ONEPASS_SHARED_TARGET" ;;
esac
unset _onepass_root

ONEPASS_JOBS="${ONEPASS_JOBS:-4}"
export CARGO_BUILD_JOBS="$ONEPASS_JOBS"
export RUST_TEST_THREADS="$ONEPASS_JOBS"
export NEXTEST_TEST_THREADS="$ONEPASS_JOBS"
