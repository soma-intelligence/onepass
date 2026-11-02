# Source this file (`. scripts/dev-env.sh`) before building or testing in a
# checkout, especially when several checkouts build at the same time.
#
# - sccache caches compiled crates by content in one shared directory, so a
#   dependency (aws-lc, SQLite, libcrux...) compiles once for every checkout.
#   Unlike a shared CARGO_TARGET_DIR, it never hands one checkout another
#   checkout's test binaries or libraries.
# - Each checkout keeps its own core/target (CARGO_TARGET_DIR is unset).
# - Builds are capped at ONEPASS_JOBS jobs (default 4) and test runs at the
#   same number of threads.

if command -v sccache >/dev/null 2>&1; then
  export RUSTC_WRAPPER=sccache
  export SCCACHE_DIR="${SCCACHE_DIR:-$HOME/Library/Caches/onepass-sccache}"
  export SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-40G}"
  # Rust compiles embed absolute paths: strip each checkout's root so a crate
  # built in one checkout is a cache hit in another (measured: 0% to 73%).
  # The sccache server reads this when it starts; `sccache --stop-server`
  # after adding a checkout.
  _onepass_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
  _onepass_roots="$_onepass_root"
  for _d in "$(dirname "$_onepass_root")"/*/; do
    [ -d "$_d.git" ] && [ "${_d%/}" != "$_onepass_root" ] && _onepass_roots="$_onepass_roots:${_d%/}"
  done
  export SCCACHE_BASEDIRS="$_onepass_roots"
  unset _onepass_root _onepass_roots _d
else
  echo "dev-env: sccache not found (brew install sccache); building without a shared cache" >&2
fi

unset CARGO_TARGET_DIR

ONEPASS_JOBS="${ONEPASS_JOBS:-4}"
export CARGO_BUILD_JOBS="$ONEPASS_JOBS"
export RUST_TEST_THREADS="$ONEPASS_JOBS"
export NEXTEST_TEST_THREADS="$ONEPASS_JOBS"
