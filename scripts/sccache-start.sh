#!/usr/bin/env bash
# Makes sure the shared sccache server runs, started from a clean
# environment. scripts/dev-env.sh and apple/scripts/build-core.sh call it
# before anything exports a deployment target.
#
# Why: the server keeps the environment it was started with and hands it to
# every compiler it runs. A server started by a compile inside build-core.sh
# inherits MACOSX_DEPLOYMENT_TARGET, IPHONEOS_DEPLOYMENT_TARGET and the
# others at once, and clang then refuses aws-lc's C files with "conflicting
# deployment targets". So the server is started here, with only the sccache
# settings, and never exits on idle (SCCACHE_IDLE_TIMEOUT=0) so that a
# compile never starts a new one later.
#
# A running server is restarted when its environment carries a deployment
# target or other sccache settings than the caller's (a checkout was added:
# SCCACHE_BASEDIRS changed), but only while nothing compiles: no queued heavy
# step (scripts/heavy.sh) and no cargo, rustc or clang process of this user,
# since stopping it fails the compiles in flight. Otherwise it only warns.
set -euo pipefail

command -v sccache >/dev/null 2>&1 || exit 0
[ -n "${SCCACHE_DIR:-}" ] || exit 0

PORT="${SCCACHE_SERVER_PORT:-4226}"
LOCK="${ONEPASS_HEAVY_LOCK:-$HOME/Library/Caches/onepass-heavy.lock}"

server_pid() {
  lsof -nP -a -u "$(id -u)" -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -1
}

compiling() {
  pgrep -u "$(id -u)" -x 'cargo|cargo-nextest|rustc|clang|cc|swift-frontend|swift-build|xcodebuild' >/dev/null 2>&1 && return 0
  # We hold the lock ourselves: no other queued step is compiling.
  [ "${ONEPASS_HEAVY_HELD:-}" = 1 ] && return 1
  [ -e "$LOCK" ] || return 1
  ! perl -MFcntl=:flock -e 'open(my $f, ">>", shift) or exit 0; exit(flock($f, LOCK_EX | LOCK_NB) ? 0 : 1)' "$LOCK"
}

pid="$(server_pid || true)"
if [ -n "$pid" ]; then
  env_line="$(ps -Eww -o command= -p "$pid" 2>/dev/null || true)"
  reason=""
  if [[ "$env_line" == *_DEPLOYMENT_TARGET=* ]]; then
    reason="it was started with a deployment target in its environment"
  elif [[ "$env_line" != *"SCCACHE_DIR=$SCCACHE_DIR"* ]] \
    || [[ "$env_line" != *"SCCACHE_BASEDIRS=${SCCACHE_BASEDIRS:-}"* ]]; then
    reason="its SCCACHE_DIR or SCCACHE_BASEDIRS differ from this checkout's"
  fi
  [ -z "$reason" ] && exit 0
  if compiling; then
    echo "sccache: not restarting the server ($reason) while something compiles;" \
      "run \`sccache --stop-server\` when no build runs" >&2
    exit 0
  fi
  echo "sccache: restarting the server: $reason" >&2
  sccache --stop-server >/dev/null 2>&1 || true
fi

env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" USER="${USER:-}" \
  SCCACHE_DIR="$SCCACHE_DIR" \
  SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-40G}" \
  SCCACHE_BASEDIRS="${SCCACHE_BASEDIRS:-}" \
  SCCACHE_IDLE_TIMEOUT=0 \
  sccache --start-server >/dev/null 2>&1 || {
    # Another caller may have started it between the check and here.
    [ -n "$(server_pid || true)" ] || { echo "sccache: the server did not start" >&2; exit 1; }
  }
